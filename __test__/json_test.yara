import "json"

rule string_array_includes {
    condition:
        json.array_includes("strArray", "one") and
        json.array_includes("strArray", "two") and
        json.array_includes("strArray", "three")
}

rule string_array_includes_nested {
    condition:
        json.array_includes("string.strArray", "one") and
        json.array_includes("string.strArray", "two") and
        json.array_includes("string.strArray", "three")
}

rule integer_array_includes {
    condition:
        json.array_includes("intArray", 1) and
        json.array_includes("intArray", 2) and
        json.array_includes("intArray", 3)
}

rule integer_array_includes_nested {
    condition:
        json.array_includes("integer.intArray", 1) and
        json.array_includes("integer.intArray", 2) and
        json.array_includes("integer.intArray", 3)
}

rule float_array_includes {
    condition:
        json.array_includes("floatArray", 1.0) and
        json.array_includes("floatArray", 2.0) and
        json.array_includes("floatArray", 3.0)
}

rule float_array_includes_nested {
    condition:
        json.array_includes("float.floatArray", 1.0) and
        json.array_includes("float.floatArray", 2.0) and
        json.array_includes("float.floatArray", 3.0)
}

rule dotted_key {
    condition:
        json.key_exists("dot\\.key")
}

rule dotted_key_sub {
    condition:
        json.key_exists("dot\\.key.subkey")
}

rule has_key_normal {
    condition:
        json.key_exists("normal_key")
}

rule get_string {
    condition:
        json.get_string_value("keykey") == "valuevalue"
}

rule get_integer {
    condition:
        json.get_integer_value("integer_number") == 42
}

rule get_float {
    condition:
        json.get_float_value("float_number") == 42.42
}