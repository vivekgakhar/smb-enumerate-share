const net = require('net')
const ntlm = require('ntlm')

const STATUS_PENDING = 0x103

// SMB message command opcodes
const NEGOTIATE = 0x00
const SESSION_SETUP = 0x01
const TREE_CONNECT = 0x03
const CREATE = 0x05
const CLOSE = 0x06
const READ = 0x08
const WRITE = 0x09
const IOCTL = 0x0B

// share types
const TEMPORARY = 0x40000000
const HIDDEN = 0x80000000
const SHARETYPES = {
	[0x00]: 'DISK_TREE',
	[0x01]: 'PRINT_QUEUE',
	[0x02]: 'COMM_DEVICE',
	[0x03]: 'IPC'
}

// common error codes
const COMMON_ERRORS = {
	0xc000000d: 'STATUS_INVALID_PARAMETER',
	0xc0000022: 'STATUS_ACCESS_DENIED',
	0xc000005e: 'STATUS_NO_LOGON_SERVERS',
	0xc000006d: 'STATUS_LOGON_FAILURE',
	0xc0000072: 'STATUS_ACCOUNT_DISABLED',
	0xc00000bb: 'STATUS_NOT_SUPPORTED',
}

const NETBIOS_HEADER = '00000000'

const SMB_HEADER = 'fe534d4240' + '0'.repeat(118)

const requestStructures = {
	[NEGOTIATE]:  '24000200010000000000000000000000000000000000000000000000000000000000000002021002',
	[SESSION_SETUP]: '190000010100000000000000580000000000000000000000',
	[TREE_CONNECT]: '0900000048000000',
	[CREATE]: '3900000002000000000000000000000000000000000000009f0112000000000007000000010000004000'
	+ '4000780000000000000000000000',
	[WRITE]: '310070' + '0'.repeat(90),
	[READ]: '310000000004' + '0'.repeat(86),
	[IOCTL]: '3900000017c0110000000000000000000000000000000000780000000000000000000000000000000000'
	+ '0000042000000100000000000000',
	[CLOSE]: '1800000000000000000000000000000000000000000000000000000000000000000000000000000000000'
}

module.exports = async function(options) {
	if(typeof options === 'string') {
		const smbUrlRegex = /^smb:\/\/(?:(?:(.*?);)?(.*?)(?::(.*?))?@)?([^:/]+)(?::(\d+))?/
		const matches = options.match(smbUrlRegex)
		if(!matches) {
			throw new Error('Invalid smb url')
		}
		options = {
			domain: matches[1],
			username: matches[2],
			password: matches[3],
			host: matches[4],
			port: matches[5]
		}
	}
	const host = options.host
	const port = options.port || 445
	const username = options.username || 'guest'
	const password = options.password || ''
	const domain = options.domain || 'WORKGROUP'
	const timeout = options.timeout || 5000

	if(!host) {
		throw new Error('No host provided')
	}
	let responsePromise, result, data, shares, done = false
	let messageid = 0, rpcMessageid = 0, sessionid = '0', treeid = 0, fileid = 0
	
	const request = message => {
		const promise = new Promise((resolve, reject) => responsePromise = {resolve, reject})
		socket.write(message)
		messageid++
		return promise
	}
	
	const confirmStatus = (status, expected) =>  {
		if(status !== expected) {
			socket.destroy()
			if(COMMON_ERRORS[status]) {
				throw new Error(COMMON_ERRORS[status])
			} else {
				throw new Error(`NTSTATUS 0x${status.toString(16)}. Expected: 0x${expected.toString(16)}`)
			}
		}
	}
	
	const createRequest = (command, params) => {
		const header = Buffer.from(NETBIOS_HEADER + SMB_HEADER, 'hex')
		let structure = Buffer.from(requestStructures[command], 'hex')

		if(command === SESSION_SETUP) {
			structure.writeInt32LE(params.length, 14)
			structure = Buffer.concat([structure, params])
		} else if(command === TREE_CONNECT) {
			structure.writeUInt16LE(params.length, 6)
			structure = Buffer.concat([structure, params])
		} else if(command === CREATE) {
			structure.writeUInt16LE(params.length, 46)
			structure = Buffer.concat([structure, params])
		} else if(command === WRITE) {
			structure.writeUInt32LE(params.length, 4)
			structure.write(fileid, 16, fileid.length, 'hex')
			structure = Buffer.concat([structure, params])
		} else if(command === READ) {
			structure.write(fileid, 16, fileid.length, 'hex')
		} else if(command === IOCTL) {
			structure.writeUInt32LE(params.length, 28)
			structure.write(fileid, 8, fileid.length, 'hex')
			structure = Buffer.concat([structure, params])
		} else if(command === CLOSE) {
			structure.write(fileid, 8, fileid.length, 'hex')
		}
		
		const buffer = Buffer.concat([header, structure])
		// write headers
		buffer.writeUInt16LE(command, 16)
		buffer.writeUInt32LE(messageid, 28)
		buffer.writeUInt32LE(treeid, 40)
		buffer.write(sessionid, 44, 8, 'hex')
		buffer.writeUInt32BE(buffer.length - 4, 0)
		return buffer
	}

	const socket = new net.Socket()
		.on('data', data => {
			const packetLength = data.readUInt32BE(0)
			if(data.length > packetLength + 4) {
				// double packet received, ignore first one (most likely STATUS_PENDING)
				data = data.slice(packetLength + 4, data.length)
			}
			const status = data.readUInt32LE(12)
			if(status !== STATUS_PENDING) {
				// only resolve when the packet we're interested in is received
				responsePromise.resolve(data)
			}
		}).on('timeout', () => {
			socket.destroy()
			responsePromise.reject(new Error('Connection timeout'))
		}).on('error', err => {
			socket.destroy()
			responsePromise.reject(err)
		}).on('end', () => {
			if(!done)
				responsePromise.reject(new Error('Connection unexpected ended'))
		})
		.connect(port, host)
	
	socket.setTimeout(timeout)
	
	/* MESSAGE PIPELINE */

	// negotiate
	result = await request(createRequest(NEGOTIATE))
	confirmStatus(result.readUInt32LE(12), 0)

	// session setup step 1
	data = ntlm.encodeType1(host, domain)
	result = await request(createRequest(SESSION_SETUP, data))
	confirmStatus(result.readUInt32LE(12), 0xC0000016)

	// session setup step 2
	sessionid = result.slice(44, 52).toString('hex')
	const nonce = ntlm.decodeType2(result.slice(76))
	data = ntlm.encodeType3(username, host, domain, nonce, password)
	result = await request(createRequest(SESSION_SETUP, data))  
	confirmStatus(result.readUInt32LE(12), 0)

	// connect to IPC$
	const path = '\\\\'+host+'\\IPC$'
	result = await request(createRequest(TREE_CONNECT, Buffer.from(path, 'ucs2')))
	confirmStatus(result.readUInt32LE(12), 0)

	// connect to srvsvc
	treeid = result.readUInt32LE(40)
	result = await request(createRequest(CREATE, Buffer.from('srvsvc', 'ucs2')))
	confirmStatus(result.readUInt32LE(12), 0)

	// bind rpc
	fileid = result.slice(132, 148).toString('hex')
	data = Buffer.from(
		'05000b03100000007400000002000000b810b810000000000200000000000100c84f32'
	+ '4b7016d30112785a47bf6ee18803000000045d888aeb1cc9119fe808002b1048600200'
	+ '000001000100c84f324b7016d30112785a47bf6ee188030000002c1cb76c1298404503'
	+ '0000000000000001000000', 'hex'
	)
	data.writeInt32LE(rpcMessageid++, 11)
	result = await request(createRequest(WRITE, data))
	confirmStatus(result.readUInt32LE(12), 0)

	// read from srvsvc
	result = await request(createRequest(READ))
	confirmStatus(result.readUInt32LE(12), 0)
	
	// send NetShareEnumAll request
	let remote_name = '\\\\'+host+'\0'
	let server_len = remote_name.length
	let server_bytes_len = server_len * 2
	if(server_len % 2 !== 0) {
		remote_name += '\0'
		server_bytes_len += 2
	}
	const base = Buffer.from(
		'050000031000000000000000000000004c00000000000f0000000200000000000000000000000000', 'hex'
	)
	base.writeInt16LE(server_bytes_len+72, 8)
	base.writeUInt32LE(rpcMessageid, 12)
	base.writeUInt32LE(server_len, 28)
	base.writeUInt32LE(server_len, 36)
	data = Buffer.concat([
		base,
		Buffer.from(remote_name, 'ucs2'),
		Buffer.from('0100000001000000040002000000000000000000ffffffff0800020000000000', 'hex')
	])
	result = await request(createRequest(IOCTL, data))
	confirmStatus(result.readUInt32LE(12), 0)

	// parse results
	shares = []
	data = result.slice(result.readUInt32LE(100) + 4)
	const sharesCount = data.readUInt32LE(36)
	let offset = 48, length
	for(let i = 0; i < sharesCount; i++) {
		const shareType = data.readUInt32LE(offset+4)
		shares[i] = {
			type: SHARETYPES[shareType & 0xFF],
			hidden: (shareType & HIDDEN) !== 0,
			temporary: (shareType & TEMPORARY) !== 0
		}
		offset += 12
	}
	for(let i = 0; i < sharesCount; i++) {
		length = data.readUInt32LE(offset+8)
		offset += 12
		shares[i].name = data.slice(offset, offset+length*2-2).toString('ucs2')
		offset += length % 2 !== 0 ? length * 2 + 2 : length * 2
		length = data.readUInt32LE(offset+8)
		offset += 12
		shares[i].comments = data.slice(offset, offset + length*2-2).toString('ucs2')
		offset += length % 2 !== 0 ? length * 2 + 2 : length * 2
	}

	// close connection
	done = true
	await request(createRequest(CLOSE)).then(() => socket.destroy())
	
	return shares
}
