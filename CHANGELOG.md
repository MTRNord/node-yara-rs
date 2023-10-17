# node-yara-rs 0.6.2 (2023-10-17)

### Bugfixes

- Also decode the utf8 bytes


# node-yara-rs 0.6.1 (2023-10-13)

### Bugfixes

- Fix windows build


# node-yara-rs 0.6.0 (2023-10-13)

### Features

- Make dots in keys of json objects work with the json module
- Overload the value_exists function to have less function duplication on the frontend of the json module
- Add get_X_value methods to json module to get the value of a key

### Internal Changes

- Ignore more unnessesary files in npmignore

# node-yara-rs 0.5.0 (2023-10-08)

### Features

- Add a json module to the used yara version

# node-yara-rs 0.4.0 (2023-10-05)

### Features

- Improve the arguments by utilizing the napi Either type

### Internal Changes

- Add Towncrier for changelog managment
- Dependencies have been updated
- Test coverage has been extended
