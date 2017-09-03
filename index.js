"use strict"
const crypto = require('crypto')

function md5(data){
    var hash = crypto.createHash('md5')
    hash.update(data)
    return hash.digest('hex')
}

function __php_bin2hex(byte){
    var tmp = new Buffer(byte, 'binary')
    return tmp.toString('hex')
}

function __php_hex2bin(strin){
    var tmp = new Buffer(strin, 'hex')
    return tmp.toString('binary')
}

function safe_base64_encode(bitmap)  {
    var tmp = new Buffer(bitmap, 'binary').toString('base64')
    tmp = tmp.replace(new RegExp(/\+/,"gm"), '-')
            .replace(new RegExp(/\//,"gm"), '_')
            .replace(new RegExp(/=/,"gm"), '')
    return tmp
}

function safe_base64_decode(str) {
    str = str.replace(/(^\s*)|(\s*$)/g, '')
        .replace(new RegExp(/-/,"gm"), '+')
        .replace(new RegExp(/_/,"gm"), '/')

    var last_len = str.length % 4;
    str = last_len == 2 ? str + '==' : (last_len == 3 ? str + '=' : str)
    str = new Buffer(str, 'base64')
    return str.toString('binary')
}

/**
 * @param int length
 * @return string
 */
function rand_str(length, tpl) {
    if (length <= 0) {
        return ''
    }
    tpl = tpl || "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    var str_list = []
    for (var i = 0; i < length; i++) {
        var idx = Math.floor(Math.random() * tpl.length)
        str_list.push(tpl[idx])
    }
    return str_list.join('')
}

/**
 * 加密函数
 * @param string string 需要加密的字符串
 * @param string key
 * @param int expiry 加密生成的数据 的 有效期 为0表示永久有效， 单位 秒
 * @param string salt
 * @param int rnd_length 动态密匙长度 byte rnd_length>=0，相同的明文会生成不同密文就是依靠动态密匙
 * @param int chk_length  校验和长度 byte rnd_length>=4 && rnd_length><=16
 * @return string 加密结果 使用了 safe_base64_encode
 */
function encode(string, key, expiry, salt, rnd_length, chk_length) {
    expiry = expiry || 0; salt = salt || 'salt'; rnd_length = rnd_length || 2; chk_length = chk_length || 4
    return authcode(string, 'ENCODE', key, expiry, salt, rnd_length, chk_length)
}

/**
 * 解密函数 使用 配置 CRYPT_KEY 作为 key  成功返回原字符串  失败或过期 返回 空字符串
 * @param string string 需解密的 字符串 safe_base64_encode 格式编码
 * @param string key
 * @param string salt
 * @param int rnd_length 动态密匙长度 byte rnd_length>=0，相同的明文会生成不同密文就是依靠动态密匙
 * @param int chk_length  校验和长度 byte rnd_length>=4 && rnd_length><=16
 * @return string 解密结果
 */
function decode(string, key, salt, rnd_length, chk_length) {
    salt = salt || 'salt'; rnd_length = rnd_length || 2; chk_length = chk_length || 4
    return authcode(string, 'DECODE', key, 0, salt, rnd_length, chk_length)
}

function int32ToByteWithLittleEndian(int32) {
    int32 = Math.abs(parseInt(int32))
    var byte0 = int32 % 256
    int32 = (int32 - byte0) / 256
    var byte1 = int32 % 256
    int32 = (int32 - byte1) / 256
    var byte2 = int32 % 256
    int32 = (int32 - byte2) / 256
    var byte3 = int32 % 256
    var chr = String.fromCharCode
    return chr(byte0) + chr(byte1) + chr(byte2) + chr(byte3)
}

function byteToInt32WithLittleEndian(byte) {
    var byte_len = byte.length
    var byte0 = byte_len >= 1 ? byte.charCodeAt(0) : 0
    var byte1 = byte_len >= 2 ? byte.charCodeAt(1) : 0
    var byte2 = byte_len >= 3 ? byte.charCodeAt(2) : 0
    var byte3 = byte_len >= 4 ? byte.charCodeAt(3) : 0
    return byte3 * 256 * 256 * 256 + byte2 * 256 * 256 + byte1 * 256 + byte0
}


/**
 * @param string _string
 * @param string operation
 * @param string _key
 * @param int _expiry
 * @param string salt
 * @param int rnd_length 动态密匙长度 byte rnd_length>=0，相同的明文会生成不同密文就是依靠动态密匙
 * @param int chk_length  校验和长度 byte rnd_length>=4 && rnd_length><=16
 * @return string
 */
function authcode(_string, operation, _key, _expiry, salt, rnd_length, chk_length) {
    rnd_length = rnd_length > 0 ? parseInt(rnd_length) : 0
    _expiry = _expiry > 0 ? parseInt(_expiry) : 0
    chk_length = chk_length > 4 ? (chk_length < 16 ? parseInt(chk_length) : 16) : 4

    var time_int = parseInt( Date.parse(new Date()) / 1000 )
    var key = md5(salt + _key + 'origin key') // 密匙
    var keya = md5(salt + key.substr(0, 16) + 'key a for crypt') // 密匙a会参与加解密
    var keyb = md5(salt + key.substr(16, 16) + 'key b for check sum') // 密匙b会用来做数据完整性验证
    
    if (operation == 'DECODE') {
        var keyc = rnd_length > 0 ? _string.substr(0, rnd_length) : '' // 密匙c用于变化生成的密文
        var cryptkey = keya + md5(salt + keya + keyc + 'merge key a and key c') // 参与运算的密匙
        // 解码，会从第 keyc_length Byte开始，因为密文前 keyc_length Byte保存 动态密匙
        var string = safe_base64_decode(_string.substr(rnd_length))
        var result = encodeByXor(string, cryptkey)
        // 验证数据有效性
        var result_len_ = result.length
        var expiry_at_ = result_len_ >= 4 ? byteToInt32WithLittleEndian(result.substr(0, 4)) : 0
        var pre_len = 4 + chk_length
        var checksum_ = result_len_ >= pre_len ? __php_bin2hex(result.substr(4, chk_length)) : 0
        var string_ = result_len_ >= pre_len ? result.substr(pre_len) : ''
        var tmp_sum = md5(salt + string_ + keyb).substr(0, 2 * chk_length)
        var test_pass = (expiry_at_ == 0 || expiry_at_ > time_int) && checksum_ == tmp_sum
        return test_pass ? string_ : ''
    } else {
        var keyc = rnd_length > 0 ? rand_str(rnd_length) : '' // 密匙c用于变化生成的密文
        var checksum = md5(salt + _string + keyb).substr(0, 2 * chk_length)
        var expiry_at = _expiry > 0 ? _expiry + time_int : 0
        var cryptkey = keya + md5(salt + keya + keyc + 'merge key a and key c') // 参与运算的密匙
        // 加密，原数据补充附加信息，共 8byte  前 4 Byte 用来保存时间戳，后 4 Byte 用来保存 checksum 解密时验证数据完整性
        var string = int32ToByteWithLittleEndian(expiry_at) + __php_hex2bin( checksum) + _string
        var result = encodeByXor(string, cryptkey)
        return keyc + safe_base64_encode(result)
    }
}

function encodeByXor(string, cryptkey) {
    var string_length = string.length
    var key_length = cryptkey.length
    var result_list = []
    var box = []
    var rndkey = []
    var a = 0, i = 0, j = 0, tmp = 0, tmp_idx = 0
    for (i = 0; i <= 255; i++) {
        box.push(i)
        rndkey.push(0)
    }
    // 产生密匙簿
    for (i = 0; i <= 255; i++) {
        rndkey[i] = cryptkey.charCodeAt(i % key_length)
    }
    
    for (j = i = 0; i < 256; i++) {
        j = (i + j + box[i] + box[j] + rndkey[i] + rndkey[j]) % 256
        tmp = box[i]
        box[i] = box[j]
        box[j] = tmp
    }
    
    // 核心加解密部分
    for (a = j = i = 0; i < string_length; i++) {
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        tmp = box[a]
        box[a] = box[j]
        box[j] = tmp
        // 从密匙簿得出密匙进行异或，再转成字符
        tmp_idx = (box[a] + box[j]) % 256
        result_list.push( String.fromCharCode(string.charCodeAt(i) ^ box[tmp_idx]) )
    }
    
    return result_list.join('')
}

module.exports = {
    safe_base64_decode,
    safe_base64_encode,
    encode,
    decode,
}