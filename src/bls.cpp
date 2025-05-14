#include <bls/bls_crypto.h>
#include <cryptonote_core/service_node_list.h>
#include <networks.h>
#include <pybind11/pybind11.h>

#include <span>
#include <stdexcept>

#include "common/guts.h"
#include "crypto/crypto.h"

namespace py = pybind11;
using namespace py::literals;

namespace oxen {

template <size_t N>
struct TypeName {
    consteval TypeName(const char (&str)[N]) { std::copy_n(str, N, c_str); }
    char c_str[N];
};

using namespace pybind11;
using namespace pybind11::detail;

template <tools::safe_to_memcpy T, TypeName Name>
struct key_caster {
    PYBIND11_TYPE_CASTER(T, const_name(Name.c_str));

    bool load(handle src, bool) {
        if (isinstance<py::bytes>(src)) {
            std::string_view view{src.cast<py::bytes>()};
            if (view.size() != sizeof(T))
                throw std::invalid_argument{
                        "Invalid "s + Name.c_str + " from bytes value: "s +
                        std::to_string(sizeof(T)) + " bytes required"s};
            value = tools::make_from_guts<T>(view);
            return true;
        } else if (isinstance<py::str>(src)) {
            std::string s_src{src.cast<py::str>()};
            std::string_view s{s_src};
            if (s.starts_with("0x") || s.starts_with("0X"))
                s.remove_prefix(2);
            if (s.size() != sizeof(T) * 2 || !oxenc::is_hex(s))
                throw std::invalid_argument{
                        "Invalid "s + Name.c_str + " from str value: "s +
                        std::to_string(2 * sizeof(T)) + " hex digits required"s};
            value = tools::make_from_hex_guts<T>(s);
            return true;
        }
        return false;
    }

    static handle cast(const T& src, return_value_policy, handle) {
        return py::bytes{tools::view_guts(src)}.release();
    }
};

}  // namespace oxen

namespace pybind11::detail {

template <>
struct type_caster<eth::bls_signature> : oxen::key_caster<eth::bls_signature, "bls_signature"> {};
template <>
struct type_caster<eth::bls_public_key> : oxen::key_caster<eth::bls_public_key, "bls_pubkey"> {};
template <>
struct type_caster<eth::address> : oxen::key_caster<eth::address, "eth_address"> {};
template <>
struct type_caster<crypto::public_key> : oxen::key_caster<crypto::public_key, "ed25519_pubkey"> {};

}  // namespace pybind11::detail

PYBIND11_MODULE(oxen_bls, m) {
    m.def(
            "bls_verify",
            [](std::string network, eth::bls_signature sig, eth::bls_public_key pk, py::bytes msg_b)
                    -> bool {
                auto nettype = cryptonote::network_type_from_string(network);
                if (nettype == cryptonote::network_type::UNDEFINED)
                    throw std::invalid_argument{"Invalid network value"};
                std::string_view msg_view{msg_b};
                std::span<const unsigned char> msg{
                        reinterpret_cast<const unsigned char*>(msg_view.data()),
                        static_cast<size_t>(msg_view.size())};

                return eth::verify(nettype, sig, pk, msg);
            },
            "network"_a,
            "signature"_a,
            "pubkey"_a,
            "message"_a,

            "Verifies a BLS signature signed for the given Oxen network."
            " Network must be one of: \"mainnet\", \"testnet\", \"stagenet\", \"devnet\"."
            " bls_pubkey is 64 bytes and signature is 128 bytes and can be given as either raw"
            " bytes values or hex str values.");

    m.def(
            "bls_registration_msg",
            [](std::string network,
               crypto::public_key pk_ed,
               eth::bls_public_key pk_bls,
               eth::address op_addr) -> py::bytes {
                auto nettype = cryptonote::network_type_from_string(network);
                if (nettype == cryptonote::network_type::UNDEFINED)
                    throw std::invalid_argument{"Invalid network value"};
                auto pop_tag = eth::build_tag_hash(eth::tag::PROOF_OF_POSSESSION, nettype);
                auto msg = tools::concat_guts<char>(pop_tag, pk_bls, op_addr, pk_ed);
                return py::bytes{msg.data(), msg.size()};
            },
            "network"_a,
            "pubkey_ed25519"_a,
            "pubkey_bls"_a,
            "operator"_a,
            "Returns the proof-of-possession message (as bytes) that is signed as part of a "
            "registration.");
}
