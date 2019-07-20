// look up tables
let to_hex_array = []
let to_byte_map = {}

for (let ord = 0; ord <= 0xff; ord++) {
  let s = ord.toString(16)
  if (s.length < 2) {
    s = '0' + s
  }
  to_hex_array.push(s)
  to_byte_map[s] = ord
}

// converter using lookups
export function bufferToHex(buffer) {
  let hex_array = []
  // (new Uint8Array(buffer)).forEach((v) => { hex_array.push(to_hex_array[v]) });
  for (let i = 0; i < buffer.length; i++) {
    hex_array.push(to_hex_array[buffer[i]])
  }
  return hex_array.join('')
}
// reverse conversion using lookups
export function hexToBuffer(s) {
  let length2 = s.length
  if (length2 % 2 != 0) {
    throw new Error('hex string must have length a multiple of 2')
  }
  let length = length2 / 2
  let result = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    let i2 = i * 2
    let b = s.substring(i2, i2 + 2)
    result[i] = to_byte_map[b]
  }
  return result
}
