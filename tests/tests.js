var assert = require('assert');
var nodekl = require('../index');

var safe_base64_encode = nodekl.safe_base64_encode
var safe_base64_decode = nodekl.safe_base64_decode

describe('safe_base64_encode and safe_base64_decode', function(){
    it('encode empty string', function(){
        var last = ''
        assert.equal(safe_base64_encode(last), '')
        assert.equal(safe_base64_decode(last), '')
        assert.equal(safe_base64_decode(safe_base64_encode(last)), last)
    })
    it('encode string', function(){
        var last = '123456'
        assert.equal(safe_base64_decode(safe_base64_encode(last)), last)
        last = '     '
        assert.equal(safe_base64_decode(safe_base64_encode(last)), last)
        last = 'adawdghfyuu'
        assert.equal(safe_base64_decode(safe_base64_encode(last)), last)
        last = 'das ^%5q34 234762 3 aqa98 e723'
        assert.equal(safe_base64_decode(safe_base64_encode(last)), last)
        last = '我的中文测试'
        assert.equal(safe_base64_decode(safe_base64_encode(last)), last)
    })
})

var encode = nodekl.encode
var decode = nodekl.decode

describe('encode and decode', function(){
    it('encode empty string', function(){
        var last = '', key = '32sadweuhrw'
        assert.equal(encode(last, key), '')
        assert.equal(decode(last, key), '')
        assert.equal(decode(encode(last, key), key), last)
    })
    it('encode string', function(){
        var last = '122324234', key = '32sadweuhrw'
        assert.equal(decode(encode(last, key), key), last)
        last = '     ', key = '32sadweuhrw'
        assert.equal(decode(encode(last, key), key), last)
        last = 'sfseghkjhuihui', key = '32sadweuhrw'
        assert.equal(decode(encode(last, key), key), last)
        last = 'das ^%5q34 234762 3 aqa98 e723', key = '32sadweuhrw'
        assert.equal(decode(encode(last, key), key), last)
        last = '122324234', key = '我的中文测试'
        assert.equal(decode(encode(last, key), key), last)
        last = '我的中文测试', key = '32sadweuhrw'
        assert.equal(decode(encode(last, key), key), last)
    })
})

describe('encode and decode from php', function(){
    it('encode string', function(){
        var test = {"key":"zT5hF$E24*(#dfS^Yq3&6A^6","test_list":{"CDveD0kGQkX6c":"","m1lFv6XGYEAe9z":"1","lJT_J__LJePfudOg":"12","dzWJrtwrqORxqOUJ4":"123","7r8Kqp3Fs3k5Dk3ZSp":"1234","q58an2EvsFuIuSevy2":"1234","qQDKgHWSuJFg-OCx-g":"1234","coJbrAR2BcNFy8IWkA":"1234","ewVITfifalugspmnN6":"1234"}}
        
        var _key = test['key']
        for(var v in test['test_list']){
            var t = test['test_list'][v]
            var t_ = decode(v, _key)
            assert.equal(t, t_)
        }
    })
})


    
