/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <jansson.h>
#include <stdio.h>
#include <yara/modules.h>
#include <yara/globals.h>
#include <string.h>

#define MODULE_NAME json

// Ensures Key exists in JSON
define_function(key_exists)
{
    char *key = strdup(string_argument(1));

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }
        token = strtok(NULL, ".");
    }

    free(key);
    free(token);

    return_integer(1);
}

// Assert String value
define_function(value_exists_string)
{
    char *key = strdup(string_argument(1));
    char *value = strdup(string_argument(2));

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    char *prevToken = strdup(token);

    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }

        strcpy(prevToken, token);
        token = strtok(NULL, ".");
    }

    const char *found = json_string_value(iter);
    if (found == NULL)
    {
        printf("no string value could be obtained from value at key\n");
        return_integer(0);
    }

    if (strcmp(found, value) != 0)
    {
        return_integer(0);
    }
    free(key);
    free(value);
    free(prevToken);
    free(token);

    return_integer(1);
}

// Assert Integer value
define_function(value_exists_integer)
{
    char *key = strdup(string_argument(1));
    int value = integer_argument(2);

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    char *prevToken = strdup(token);

    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }

        strcpy(prevToken, token);
        token = strtok(NULL, ".");
    }

    double foundNumber = json_number_value(iter);
    if (foundNumber == 0.0)
    {
        printf("no number value could be obtained from value at key\n");
        return_integer(0);
    }
    int found = (int)foundNumber;

    if (found != value)
    {
        return_integer(0);
    }
    free(key);
    free(prevToken);
    free(token);

    return_integer(1);
}

// Assert Regex value
define_function(value_exists_regex)
{
    YR_SCAN_CONTEXT *context = yr_scan_context();
    char *key = strdup(string_argument(1));
    RE *value = regexp_argument(2);

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    char *prevToken = strdup(token);

    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }

        strcpy(prevToken, token);
        token = strtok(NULL, ".");
    }

    const char *found = json_string_value(iter);
    if (found == NULL)
    {
        printf("no string value could be obtained from value at key\n");
        return_integer(0);
    }
    if (yr_re_match(context, value, found) <= 0)
    {
        return_integer(0);
    }

    free(key);
    free(prevToken);
    free(token);

    return_integer(1);
}

// Assert Float value
define_function(value_exists_float)
{
    char *key = strdup(string_argument(1));
    double value = float_argument(2);

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    char *prevToken = strdup(token);

    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }

        strcpy(prevToken, token);
        token = strtok(NULL, ".");
    }

    double found = json_number_value(iter);
    if (found == 0.0)
    {
        printf("no number value could be obtained from value at key\n");
        return_integer(0);
    }

    if (found != value)
    {
        return_integer(0);
    }
    free(key);
    free(prevToken);
    free(token);

    return_integer(1);
}

// String Array includes
define_function(string_array_includes)
{
    char *key = strdup(string_argument(1));
    char *value = strdup(string_argument(2));

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    char *prevToken = strdup(token);

    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }

        strcpy(prevToken, token);
        token = strtok(NULL, ".");
    }

    json_t *array = iter;
    bool isArray = json_is_array(array);

    size_t index;
    json_t *val;

    json_array_foreach(array, index, val)
    {
        json_t *element = json_array_get(array, index);
        const char *found = json_string_value(element);
        if (strcmp(found, value) == 0)
        {
            return_integer(1);
        }
    }

    free(array);
    free(key);
    free(key);
    free(value);
    free(prevToken);
    free(token);

    return_integer(0);
}
// Integer Array includes
define_function(integer_array_includes)
{
    char *key = strdup(string_argument(1));
    int value = integer_argument(2);

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    char *prevToken = strdup(token);

    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }

        strcpy(prevToken, token);
        token = strtok(NULL, ".");
    }

    json_t *array = iter;
    bool isArray = json_is_array(array);

    size_t index;
    json_t *val;

    json_array_foreach(array, index, val)
    {
        json_t *element = json_array_get(array, index);
        double foundNumber = json_number_value(element);
        if (foundNumber == 0.0)
        {
            printf("no number value could be obtained from value at key\n");
            return_integer(0);
        }
        int found = (int)foundNumber;

        if (found == value)
        {
            return_integer(1);
        }
    }

    free(array);
    free(key);
    free(key);
    free(value);
    free(prevToken);
    free(token);

    return_integer(0);
}
// Float Array includes
define_function(float_array_includes)
{
    char *key = strdup(string_argument(1));
    double value = float_argument(2);

    json_t *json = yr_module()->data;
    if (json == NULL)
    {
        return_integer(0);
    }

    // Split key into possible subcomponents - separated by '.'
    json_t *iter = json;
    char *token = strtok(key, ".");
    char *prevToken = strdup(token);

    while (token != NULL)
    {
        iter = json_object_get(iter, token);
        if (iter == NULL)
        {
            return_integer(0);
        }

        strcpy(prevToken, token);
        token = strtok(NULL, ".");
    }

    json_t *array = iter;
    bool isArray = json_is_array(array);

    size_t index;
    json_t *val;

    json_array_foreach(array, index, val)
    {
        json_t *element = json_array_get(array, index);
        double found = json_number_value(element);
        if (found == 0.0)
        {
            printf("no number value could be obtained from value at key\n");
            return_integer(0);
        }

        if (found == value)
        {
            return_integer(1);
        }
    }

    free(array);
    free(key);
    free(key);
    free(prevToken);
    free(token);

    return_integer(0);
}

begin_declarations;

declare_function("key_exists", "s", "i", key_exists);
declare_function("value_exists", "ss", "i", value_exists_string);
declare_function("value_exists", "si", "i", value_exists_integer);
declare_function("value_exists", "sr", "i", value_exists_regex);
declare_function("value_exists", "sf", "i", value_exists_float);
declare_function("string_array_includes", "ss", "i", string_array_includes);
declare_function("integer_array_includes", "si", "i", integer_array_includes);
declare_function("float_array_includes", "sf", "i", float_array_includes);
end_declarations;

int module_initialize(YR_MODULE *module)
{
    return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE *module)
{
    return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT *context,
    YR_OBJECT *module_object,
    void *module_data,
    size_t module_data_size)
{
    // Get first Memory Block
    YR_MEMORY_BLOCK *block = first_memory_block(context);
    const uint8_t *block_data = block->fetch_data(block);

    // Parse and Save JSON to Module
    json_error_t json_error;
    int flags = JSON_DECODE_INT_AS_REAL | JSON_ALLOW_NUL;

    json_t *json = json_loads((const char *)block_data, flags, &json_error);
    if (!json)
    {
        // fprintf(stderr, "most likely not a json file. error on line %d: %s\n", json_error.line, json_error.text);
        // NOT a JSON file or a VALID JSON FILE
        // YR_DEBUG_FPRINTF(2, stderr, "most likely not a json file. error on line %d: %s\n", json_error.line, json_error.text);
        module_object->data = NULL;
        return ERROR_SUCCESS;
    }

    // JSON is valid
    module_object->data = json;

    return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT *module_object)
{
    free(module_object->data);
    return ERROR_SUCCESS;
}
