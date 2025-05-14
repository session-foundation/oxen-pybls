# oxen-pybls -- Python oxen-core BLS bindings

Install with pip.  Requires that the `liboxen-dev` package is installed.

Example usage:

```Python
import oxen_bls

# Each of these can be given as hex (0x-prefixed or not), or bytes:
pk_ed = bytes.fromhex("f4a895743bd4171ed97bdf162be9f6f4a1013a757dfedfdc7f12a125a74c08d7")
pk_bls = "214cdf23f1c4898ef00633c2451297835d4e4ab5adfdf6f82bbf4c7144413bdb0e11d11ab513e899ab8f753c4194196fcf98df681f98baa23ad0023361c4dc47"
op = "0xAbcDEF1234ABCDEf1234ABcdef1234ABCDef1234"

reg_msg = oxen_bls.bls_registration_msg("testnet", pk_ed, pk_bls, op)

signature = "0a36ce74d46a1fc2483f563e3f3d2f6766bcf21ba6d04dc55f02fc118150c6342951fc774625de7fe5fa2d0bcbd2a464b1d0e4c8c8dd3001dc2b252a7b97096d151e8e74d5b6df581ccb3957ad7c55f8691c29b1fd79c45959eab5d549a9e01b014d5a5fb7c9e6790a359fd76b62420c37d3281ef6b49978dcb32d740e2e6173"
if oxen_bls.bls_verify("testnet", signature, pk_bls, reg_msg):
    print("Signature verified!")
else:
    print("SIGNATURE FAILED!")
```
