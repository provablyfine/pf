@echo off
rem A stand-in for sendmail on Windows: mirrors fake_sendmail.sh (see there for the contract).
rem Windows's CreateProcess cannot exec a .sh shebang script directly, so mailer.py's tests pick
rem this file instead when running on win32.
if defined FAKE_SENDMAIL_DELAY_SECONDS ping -n %FAKE_SENDMAIL_DELAY_SECONDS% 127.0.0.1 >nul
if defined FAKE_SENDMAIL_FAIL (
    echo boom 1>&2
    exit /b 1
)
more > "%FAKE_SENDMAIL_OUT%"
