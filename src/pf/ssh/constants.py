import enum


@enum.unique
class RSA(enum.IntEnum):
    SHA2_256 = 0x02
    SHA2_512 = 0x04


@enum.unique
class ChannelMsg(enum.IntEnum):
    OPEN = 90
    OPEN_CONFIRMATION = 91
    OPEN_FAILURE = 92
    WINDOW_ADJUST = 93
    DATA = 94
    EOF = 96
    CLOSE = 97
