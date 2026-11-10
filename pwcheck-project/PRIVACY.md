# Privacy Notice

**pwcheck** is designed so that your passwords never leave your computer.

- **No storage.** Passwords are held in memory only while being evaluated. Nothing is written to disk.
- **No logging.** The program does not log passwords, and error messages and feedback never contain any part of the password.
- **No transmission.** The program makes no network connections. The common-password list is a local text file.
- **Safe input.** Passwords are never accepted as command-line arguments (these appear in shell history and process lists). They are read with hidden input (`getpass`) or from standard input.
- **Generated passwords** are printed once to your terminal and are not retained.

Passwords you test here should still be treated with care: do not test a password you currently use on a shared or monitored machine.
