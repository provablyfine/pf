import collections
import logging


logger = logging.getLogger(__name__)


class Table:
    def __init__(self, database, table):
        self._database = database
        self._table = table
        names = [col_name for col_name, col in table.columns.items()]
        self._tup = collections.namedtuple(table.name, names)

    async def create(self, **kwargs):
        statement = self._table.insert().values(**kwargs)
        result = await self._database.execute(statement)
        return result

    def _where(self, statement, **kwargs):
        for k, v in kwargs.items():
            column = self._table.columns[k]
            if isinstance(v, (list, tuple, set)):
                statement = statement.where(column.in_(v))
            else:
                statement = statement.where(column==v)
        return statement

    async def read_one(self, **kwargs):
        statement = self._table.select()
        statement = self._where(statement, **kwargs)
        row = await self._database.fetch_one(statement)
        if row is None:
            return None
        return self._tup(**row)

    async def read_all(self, **kwargs):
        statement = self._table.select()
        statement = self._where(statement, **kwargs)
        rows = await self._database.fetch_all(statement)
        return [self._tup(**row) for row in rows]

    def update(self, **kwargs):
        class Update:
            def __init__(self, outer, statement):
                self._outer = outer
                self._statement = statement

            async def where(self, **kwargs):
                statement = self._outer._where(self._statement, **kwargs)
                await self._outer._database.execute(statement)
        statement = self._table.update().values(**kwargs)
        return Update(self, statement)

    async def delete(self, **kwargs):
        statement = self._table.delete()
        statement = self._where(statement, **kwargs)
        await self._database.execute(statement)


class Dao:
    def __init__(self, database, metadata):
        self._database = database
        self._metadata = metadata
        self._tables = {}

    def __getattr__(self, name):
        table = self._tables.get(name)
        if table is not None:
            return table
        if name not in self._metadata.tables:
            raise AttributeError
        table = Table(self._database, self._metadata.tables[name])
        self._tables[name] = table
        return table


def create(database, metadata):
    return Dao(database, metadata)
