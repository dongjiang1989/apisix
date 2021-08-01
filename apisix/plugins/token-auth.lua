local core     = require("apisix.core")
local resty_rsa = require("resty.rsa")
local plugin_name = "token-auth"
local ngx = ngx

local schema = {
    type = "object",
    properties = {
        header_name = {
            type = "string",
            enum = {"X-Token", "saasToken"},
            default = "X-Token"
        },
        rsa_key = {type = "string", minLength = 1, maxLength = 2048},
    },
    required = {"header_name", "rsa_key"},
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
    local priv, err = resty_rsa:new({
            private_key = conf.rsa_key,
            key_type = resty_rsa.KEY_TYPE.PKCS1,
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
    core.log.info("request token-auth :", key)
    if key then
        local index = string.find(key,"C_")
        if index ~= 1 then
            local priv, _ = resty_rsa:new({
                private_key = conf.rsa_key,
                padding = resty_rsa.PADDING.RSA_PKCS1_PADDING,
            })
            if priv then
                local decode_b64 = ngx.decode_base64(key)
                if decode_b64 then
                    local _, err = priv:decrypt(decode_b64)
                    if err then
                        return 401, {errno = 401, errmsg = "Invalid x-token key in request"}
                    end
                else
                    return 401, {errno = 401, errmsg = "Invalid x-token key in request"}
                end
            end
        end
    end 
    core.log.info("hit token-auth rewrite")
end

return _M
