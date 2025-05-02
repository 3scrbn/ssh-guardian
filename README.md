SSH guardian (Linux only) that, when properly configured, is triggered whenever a new SSH connection is initiated. It prompts for an additional password or passphrase before granting access to the terminal. It also intercepts the "Ctrl + C" key combination to prevent easy escape.

This is useful for protecting exposed user accounts that rely on password-based authentication. If an attacker guesses the user's password, they would then have a limited number of attempts to guess this second password before being able to execute commands or access the terminal.
