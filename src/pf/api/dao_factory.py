import collections
import logging
import types

logger = logging.getLogger(__name__)


class Table:
    def __init__(self, connection, table):
        self._connection = connection
        self._table = table
        names = [col_name for col_name, col in table.columns.items()]
        self._tup = collections.namedtuple(table.name, names)

    @property
    def columns(self):
        return types.SimpleNamespace(self._table.columns)

    def create(self, **kwargs) -> int|None:
        statement = self._table.insert().values(**kwargs)
        result = self._connection.execute(statement)
        primary_key = result.inserted_primary_key
        if len(primary_key) == 0:
            return None
        elif len(primary_key) == 1:
            return primary_key[0]
        else:
            assert False

    def _where(self, statement, *args, **kwargs):
        for arg in args:
            statement = statement.where(arg)
        for k, v in kwargs.items():
            column = self._table.columns[k]
            if isinstance(v, (list, tuple, set)):
                statement = statement.where(column.in_(v))
            else:
                statement = statement.where(column==v)
        return statement

    def read_one(self, *args, **kwargs):
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        for row in rows:
            return self._tup(*row)
        return None

    def read_all(self, *args, **kwargs):
        statement = self._table.select()
        statement = self._where(statement, *args, **kwargs)
        rows = self._connection.execute(statement)
        return [self._tup(*row) for row in rows]

    def update(self, **kwargs):
        class Update:
            def __init__(self, outer, statement):
                self._outer = outer
                self._statement = statement

            def where(self, **kwargs):
                statement = self._outer._where(self._statement, **kwargs)
                self._outer._connection.execute(statement)
        statement = self._table.update().values(**kwargs)
        return Update(self, statement)

    def delete(self, **kwargs):
        statement = self._table.delete()
        statement = self._where(statement, **kwargs)
        self._connection.execute(statement)


class Dao:
    def __init__(self, connection, metadata):
        self._connection = connection
        self._metadata = metadata
        self._tables = {}

    def __getattr__(self, name):
        table = self._tables.get(name)
        if table is not None:
            return table
        if name not in self._metadata.tables:
            raise AttributeError
        table = Table(self._connection, self._metadata.tables[name])
        self._tables[name] = table
        return table


def create(connection, metadata):
    return Dao(connection, metadata)
