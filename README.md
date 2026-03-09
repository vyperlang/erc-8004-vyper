<p align="center">
  <img src="vyper-logo.png" width="140" alt="Vyper logo">
</p>

# erc-8004-vyper

Vyper reference implementation of [ERC-8004: Trustless Agents](https://eips.ethereum.org/EIPS/eip-8004).

## Contracts

| Contract | Description |
|----------|-------------|
| `IdentityRegistry.vy` | ERC-721 agent registration with metadata, URI storage, and wallet verification (EIP-712 / ERC-1271) |
| `ReputationRegistry.vy` | Feedback, revocation, response tracking, and on-chain summary aggregation |
| `ValidationRegistry.vy` | Validation request/response lifecycle with designated validators |

## Dependencies

- [Vyper](https://docs.vyperlang.org/) ~0.4.3
- [Moccasin](https://github.com/Cyfrin/moccasin) (build & test framework)
- [Snekmate](https://github.com/pcaversaccio/snekmate) 0.1.2 (ERC-721, Ownable modules)
- [Titanoboa](https://github.com/vyperlang/titanoboa) (test backend)

## Build

```
mox compile
```

## Test

```
mox test
```

108 tests across the three contracts.

## Deploy

```
mox run deploy
```

Deploys all three contracts in dependency order (IdentityRegistry, then ReputationRegistry and ValidationRegistry with the identity address). For a live network, add a network section to `moccasin.toml` and run:

```
mox run deploy --network <network-name> --account <keystore>
```

## Reference

- [EIP-8004 spec](https://eips.ethereum.org/EIPS/eip-8004)
- [Solidity reference implementation](https://github.com/erc-8004/erc-8004-contracts)
- [Cairo port](https://github.com/Akashneelesh/erc8004-cairo)

## License

[MIT](LICENSE)

---

*This is an unaudited reference implementation provided for educational and development purposes only. It is not production-ready software. Use at your own risk. The authors accept no liability for any losses or damages arising from its use or deployment.*
