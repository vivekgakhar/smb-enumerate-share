# smb-enumerate-shares
> Enumeration of SMB shares for Node.js

smb-enumerate-share provides a single function that takes a number of parameters and will return a promise with the available shares on the provided server

## Install
```
$ npm install smb-enumerate-share
```

## Usage
### `smbEnumerateShare(options)`
Retrieves the shares available on the host given in the options. The `options` parameter can have the following properties:

- `host` **(required)** - The host to list the shares of. Can be a name or an ip address.
- `port` (optional) - The port to connect to. Defaults to *445*.
- `username` (optional) - The username of an account on the server. Defaults to *guest*
- `password` (optional) - The password of the account. Defaults to *empty*
- `domain` (optional) - The SMB NT domain. Defaults to *WORKGROUP*
- `timeout` (optional) - The length of time in milliseconds the connection will wait for a response from the server. Defaults to *5000*

Options may also be an SMB connection url string of the following format:

`smb://[[<domain>;]<username>[:<password>]@]<host>[:<port>][/<path>]`

This returns a **promise** resolving in an **array** of share objects. Each object has the following properties:

- `name` - The name of the share
- `hidden` - Whether this share is tagged as hidden. These shares normally end in a dollar sign
- `temporary` - Whether this share is marked as temporary
- `comments` - Comments on this share set by the server
- `type` - The share type which is one of the following: `"DISK_TREE"`, `"PRINT_QUEUE"`, `"COMM_DEVICE"` or `"IPC"`

## Examples
```js
const smbEnumerateShares = require('smb-enumerate-share')

// enumerate shares on host 'myserver'
smbEnumerateShares({host: 'myserver'})
  .then(shares => {
    for(let share of shares) {
      console.log(share.name)
    }
  })
  .catch(err => {
    // handle an error
  })

// or use the smb url syntax
smbEnumerateShares('smb://admin:test2@myserver/')
  .then(shares => console.log(shares))

```

## Bugs & Issues

This package is designed to be small and efficient, which means it does not have proper network package parsing. Problems may occur in non-typical situations. Please report issues in the issue tracker to improve this project.
