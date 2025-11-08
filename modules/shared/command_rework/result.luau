export type Result<T, E> = {
	value: nil,
	error: E,
} & {
	value: T,
	error: nil,
}

local function unwrap<T, E>(result: Result<T, E>): T
	if not result.value then
		error(result.error, 2)
	end

	return result.value
end

local function is_ok<T, E>(result: Result<T, E>)
	return result.error == nil
end

local function ok<T, E>(value: T): Result<T, E>
	return {
		value = value,
		error = nil,
	}
end

local function err<T, E>(error: E): Result<T, E>
	return {
		value = nil,
		error = error,
	}
end

return table.freeze({
	unwrap = unwrap,
	is_ok = is_ok,
	ok = ok,
	err = err,
})
