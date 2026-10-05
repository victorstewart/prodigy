#pragma once

#include <type_traits>
#include <services/bitsery.h>

template <typename T>
struct ProdigyPersistentSerializerIsWriter
    : std::bool_constant<[] constexpr {
        if constexpr (requires { T::isProdigyPersistentWriter; }) return T::isProdigyPersistentWriter;
        return false;
      }()> {
};

template <typename OutputAdapter, typename Context>
struct ProdigyPersistentSerializerIsWriter<bitsery::Serializer<OutputAdapter, Context>> : std::true_type {
};

