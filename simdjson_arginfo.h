/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: d50d4677f5bf3f4ea6321f602cc117317b508be6 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_simdjson_is_valid, 0, 1, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, json, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, depth, IS_LONG, 0, "512")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_simdjson_decode, 0, 1, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, json, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, associative, _IS_BOOL, 0, "false")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, depth, IS_LONG, 0, "512")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_simdjson_key_value, 0, 2, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO(0, json, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, associative, _IS_BOOL, 0, "false")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, depth, IS_LONG, 0, "512")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_simdjson_key_count, 0, 2, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, json, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, depth, IS_LONG, 0, "512")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, throw_if_uncountable, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_simdjson_key_exists, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, json, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, depth, IS_LONG, 0, "512")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_simdjson_cleanup, 0, 0, IS_TRUE, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_simdjson_encode, 0, 1, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, depth, IS_LONG, 0, "512")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_simdjson_encode_to_stream, 0, 2, _IS_BOOL, 0)
	ZEND_ARG_TYPE_INFO(0, value, IS_MIXED, 0)
	ZEND_ARG_OBJ_INFO(0, res, resource, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, flags, IS_LONG, 0, "0")
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, depth, IS_LONG, 0, "512")
ZEND_END_ARG_INFO()


ZEND_FUNCTION(simdjson_is_valid);
ZEND_FUNCTION(simdjson_decode);
ZEND_FUNCTION(simdjson_key_value);
ZEND_FUNCTION(simdjson_key_count);
ZEND_FUNCTION(simdjson_key_exists);
ZEND_FUNCTION(simdjson_cleanup);
ZEND_FUNCTION(simdjson_encode);
ZEND_FUNCTION(simdjson_encode_to_stream);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(simdjson_is_valid, arginfo_simdjson_is_valid)
	ZEND_FE(simdjson_decode, arginfo_simdjson_decode)
	ZEND_FE(simdjson_key_value, arginfo_simdjson_key_value)
	ZEND_FE(simdjson_key_count, arginfo_simdjson_key_count)
	ZEND_FE(simdjson_key_exists, arginfo_simdjson_key_exists)
	ZEND_FE(simdjson_cleanup, arginfo_simdjson_cleanup)
	ZEND_FE(simdjson_encode, arginfo_simdjson_encode)
	ZEND_FE(simdjson_encode_to_stream, arginfo_simdjson_encode_to_stream)
	ZEND_FE_END
};


static const zend_function_entry class_SimdJsonException_methods[] = {
	ZEND_FE_END
};


static const zend_function_entry class_SimdJsonValueError_methods[] = {
	ZEND_FE_END
};

static zend_class_entry *register_class_SimdJsonException(zend_class_entry *class_entry_RuntimeException)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "SimdJsonException", class_SimdJsonException_methods);
	class_entry = zend_register_internal_class_ex(&ce, class_entry_RuntimeException);

	return class_entry;
}

static zend_class_entry *register_class_SimdJsonValueError(zend_class_entry *class_entry_ValueError)
{
	zend_class_entry ce, *class_entry;

	INIT_CLASS_ENTRY(ce, "SimdJsonValueError", class_SimdJsonValueError_methods);
	class_entry = zend_register_internal_class_ex(&ce, class_entry_ValueError);

	return class_entry;
}
