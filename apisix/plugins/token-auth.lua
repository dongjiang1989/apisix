local core     = require("apisix.core")
local resty_rsa = require("resty.rsa")
local plugin_name = "token-auth"

local schema = {
    type = "object",
    properties = {
    	    header_name = {
            type = "string",
            enum = {"X-Token"},
            default = "X-Token"
        },
        rsa_public_key = {type = "string", minLength = 1, maxLength = 256},
        algorithm ={
            type = "string",
            enum = {"SHA256"},
            default = "SHA256"
        },
    },
    required = {"header_name", "rsa_public_key"},
}


local _M = {
    version = 0.1,
    priority = 4123,
    type = 'auth',
    name = plugin_name,
    schema = schema,
}

local function create_rsa_obj(conf)
    core.log.info("create new resty rsa plugin instance")
    local pub, err = resty_rsa:new({
    		public_key = conf.rsa_public_key,
    		padding = resty_rsa.PADDING.RSA_PKCS1_PADDING,
    		algorithm = conf.algorithm,
	})
	if err then
    	return nil
	end
	return pub
end


function _M.check_schema(conf)
    core.log.info("input conf: ", core.json.delay_encode(conf))
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end
    return true
end


function _M.rewrite(conf, ctx)
    local key = core.request.header(ctx, conf.header_name)
    if key then
        local pub, _ = resty_rsa:new({
            public_key = conf.rsa_public_key,
            key_type = resty_rsa.KEY_TYPE.PKCS8,
        })
        if pub then
            local _, err = pub:decrypt(key)
            if err then
                return 401, {message = "Invalid x-token key in request"}
            end
        end
    end 
    core.log.info("hit token-auth rewrite")
end

return _M

