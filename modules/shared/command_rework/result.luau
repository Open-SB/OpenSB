export type Result<T, E> = {
	inner: T,
	ok: true,
} | {
	inner: E,
	ok: false,
}
-- export type Result<T, E> = {
-- 	value: nil,
-- 	error: E,
-- } & {
-- 	value: T,
-- 	error: nil,
-- }

local function unwrap<T, E>(result: Result<T, E>): T
	if result.ok then
		return result.inner
	else
		return error(result.inner, 2)
	end
end

local function unwrap_err<T, E>(result: Result<T, E>): E
	if result.ok then
		return error("Called unwrap_err on a Ok Result", 2)
	end

	return result.inner
end

local function is_ok<T, E>(result: Result<T, E>)
	return result.ok
end

local function ok<T, E>(value: T): Result<T, E>
	return {
		inner = value,
		ok = true,
	}
end

local function err<T, E>(error: E): Result<T, E>
	return {
		inner = error,
		ok = false,
	}
end

return table.freeze({
	unwrap = unwrap,
	unwrap_err = unwrap_err,
	is_ok = is_ok,
	ok = ok,
	err = err,
})
