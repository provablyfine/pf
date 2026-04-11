import collections
import logging
import types
import typing
import dataclasses

import sqlalchemy

logger = logging.getLogger(__name__)

T = typing.TypeVar("T")


class Table(typing.Generic[T]):
    def __init__(
        self,
        connection: sqlalchemy.engine.Connection,
        table: sqlalchemy.Table,
        row_type: type[T] | None = None,
    ) -> None:
        self._connection = connection
        self._table = table
        names = [col_name for col_name in table.columns.keys()]
        # If row_type is provided (typed Dao), use it to construct rows.
        # Otherwise, fall back to dynamic namedtuple (untyped Dao.__getattr__ path).
        self._tup: type = row_type if row_type is not None else collections.namedtuple(table.name, names)  # type: ignore[misc]
        self.columns = types.SimpleNamespace(**dict(table.columns))  # type: ignore[misc]

    @property
    def column(self) -> types.SimpleNamespace:
        return self.columns

    def create(self, **kwargs: typing.Any) -> int | None:
        statement = self._table.insert().values(**kwargs)
        result = self._connection.execute(statement)
        primary_key: typing.Any = result.inserted_primary_key
        if primary_key is None or len(primary_key) == 0:
            return None
        if len(primary_key) == 1:
            return primary_key[0]
        raise AssertionError("Multiple primary keys not supported")

    def _where(self, statement: typing.Any, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        for arg in args:
            statement = statement.where(arg)
        for k, v in kwargs.items():
            column = self._table.columns[k]
            if isinstance(v, (list, tuple, set)):
                statement = statement.where(column.in_(v))  # type: ignore[arg-type]
            else:
                statement = statement.where(column == v)
        return statement

    def read_one(self, *args: typing.Any, **kwargs: typing.Any) -> T | None:
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        for row in rows:
            return self._tup(*row)  # type: ignore[return-value]
        return None

    def read_all(self, *args: typing.Any, **kwargs: typing.Any) -> list[T]:
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        return [self._tup(*row) for row in rows]  # type: ignore[misc]

    def update(self, **kwargs: typing.Any) -> "Update":
        statement = self._table.update().values(**kwargs)
        return Update(self, statement)

    def delete(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        statement = self._table.delete()
        statement = self._where(statement, *args, **kwargs)
        self._connection.execute(statement)


class Update:
    def __init__(self, outer: Table, statement: typing.Any) -> None:
        self._outer = outer
        self._statement = statement

    def where(self, **kwargs: typing.Any) -> None:
        statement = self._outer._where(self._statement, **kwargs)  # type: ignore[protected-access]
        self._outer._connection.execute(statement)  # type: ignore[protected-access]


class Dao:
    def __init__(self, connection: sqlalchemy.engine.Connection, metadata: sqlalchemy.MetaData) -> None:
        self._connection = connection
        self._metadata = metadata
        self._tables: dict[str, Table] = {}

    def __getattr__(self, name: str) -> Table:
        table = self._tables.get(name)
        if table is not None:
            return table
        if name not in self._metadata.tables:
            raise AttributeError(f"Table '{name}' not found")
        table = Table(self._connection, self._metadata.tables[name])
        self._tables[name] = table
        return table


def create(connection: sqlalchemy.engine.Connection, metadata: sqlalchemy.MetaData) -> Dao:
    return Dao(connection, metadata)

@dataclasses.dataclass
class Col:
    """Column metadata for use in Annotated type hints.

    Carries SQLAlchemy-specific options that can't be inferred from Python types.
    Used in NamedTuple field annotations to specify primary_key, unique, index, etc.

    Example:
        class IdentityRow(typing.NamedTuple):
            id: typing.Annotated[int, Col(primary_key=True)]
            name: str
    """

    sa_type: sqlalchemy.types.TypeEngine | None = None
    primary_key: bool = False
    nullable: bool = False
    unique: bool = False
    index: bool = False
    server_default: typing.Any = None  # str or sqlalchemy SQL expression


def _infer_sa_type(python_type: type) -> sqlalchemy.types.TypeEngine:
    """Infer SQLAlchemy type from a Python type annotation."""
    # Strip Optional/Union wrappers
    origin = typing.get_origin(python_type)
    if origin is typing.Union:
        args = typing.get_args(python_type)
        if type(None) in args:
            # Optional[X] — recurse on the non-None type
            non_none = next(arg for arg in args if arg is not type(None))
            return _infer_sa_type(non_none)

    if python_type is int:
        return sqlalchemy.Integer()
    elif python_type is str:
        return sqlalchemy.String()
    elif python_type is bool:
        return sqlalchemy.Boolean()
    elif python_type is bytes:
        return sqlalchemy.LargeBinary()
    elif origin in (dict, list):
        return sqlalchemy.JSON()
    else:
        raise ValueError(f"Cannot infer SQLAlchemy type from {python_type}")


def _is_optional(hint: type) -> bool:
    """Check if a type hint is Optional[T] (Union[T, None])."""
    origin = typing.get_origin(hint)
    if origin is typing.Union:
        args = typing.get_args(hint)
        return type(None) in args
    return False


def make_table(
    name: str,
    metadata: sqlalchemy.MetaData,
    row_cls: type,
    *constraints_and_indexes: typing.Any,
    **table_kwargs: typing.Any,
) -> sqlalchemy.Table:
    """Generate a SQLAlchemy Table from a typed NamedTuple class.

    The NamedTuple is the single source of truth for column names and Python types.
    Column order in the generated Table matches field order in the NamedTuple.

    Args:
        name: Table name
        metadata: SQLAlchemy MetaData instance
        row_cls: A NamedTuple class. Fields are columns; Annotated values with Col()
                 provide SQLAlchemy-specific options.
        *constraints_and_indexes: Additional Table constraints/indexes (UniqueConstraint, Index)
        **table_kwargs: Additional table-level options (e.g. sqlite_autoincrement=True)

    Returns:
        A SQLAlchemy Table instance
    """
    hints = typing.get_type_hints(row_cls, include_extras=True)
    columns: list[sqlalchemy.Column] = []

    for field_name, hint in hints.items():
        col_spec = Col()
        python_type = hint

        # Extract Col metadata from Annotated
        if typing.get_origin(hint) is typing.Annotated:
            python_type, *extras = typing.get_args(hint)
            for extra in extras:
                if isinstance(extra, Col):
                    col_spec = extra
                    break

        sa_type = col_spec.sa_type or _infer_sa_type(python_type)
        nullable = col_spec.nullable or _is_optional(python_type)

        # Construct Column with explicit parameters to satisfy type stubs
        col = sqlalchemy.Column(
            field_name,
            sa_type,
            primary_key=col_spec.primary_key,
            nullable=nullable,
            unique=col_spec.unique or False,
            index=col_spec.index or False,
            server_default=col_spec.server_default,
        )
        columns.append(col)

    return sqlalchemy.Table(name, metadata, *columns, *constraints_and_indexes, **table_kwargs)
