import enum


@enum.unique
class RSA(enum.IntEnum):
    SHA2_256 = 0x02
    SHA2_512 = 0x04
