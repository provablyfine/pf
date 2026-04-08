import collections
import logging
import types
import typing

import sqlalchemy

logger = logging.getLogger(__name__)


class Table:
    def __init__(self, connection: sqlalchemy.engine.Connection, table: sqlalchemy.Table) -> None:
        self._connection = connection
        self._table = table
        names = [col_name for col_name in table.columns.keys()]
        self._tup = collections.namedtuple(table.name, names)  # type: ignore[misc]
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

    def read_one(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        for row in rows:
            return self._tup(*row)
        return None

    def read_all(self, *args: typing.Any, **kwargs: typing.Any) -> list[typing.Any]:
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        return [self._tup(*row) for row in rows]

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