# Ixian Core

**Ixian Core** is the official SDK and foundation of the [Ixian Platform](https://www.ixian.io).
It provides the essential building blocks for decentralized, **self-authenticated, post-quantum-secure communication** and
is the main component of all Ixian services and applications - including [Ixian DLT](https://github.com/ixian-platform/Ixian-DLT),
[Ixian S2](https://github.com/ixian-platform/Ixian-S2), [Spixi](https://github.com/ixian-platform/Spixi), wallets, miners, and
third-party applications.

With Ixian Core, developers can build **secure-by-design applications** without relying on third parties, central servers, or
temporary trust systems.

---

## 🚀 Why Ixian Platform?

The Ixian Platform redefines how devices and people connect: **no passwords, no certificate authorities, no centralized
bottlenecks**.
Instead, Ixian introduces **cryptographic self-authentication**, **secure client discovery via cryptographic addresses**, and
**post-quantum resilience**, making it the foundation for future-ready communications and decentralized services.

### Key Innovations

* 🧬 **Self-authentication** - Every user, device, or system proves its identity cryptographically
* 🌐 **Presence-based Client Discovery** - Lookup by **cryptographic address**, not IP or DNS, eliminating the need for SSL/TLS
certificate authorities
* 🔒 **Uncompromising Security** - State-of-the-art AES and ChaCha20-Poly1305 dual encryption
* ⚛️ **Post-Quantum Resilience** - Hybrid RSA, ECDH, and ML-KEM (FIPS 203) key exchange ensures security well into the **2030s, 2040s, and
beyond**
* 🕊️ **Massive Scalability (Starling)** - Custom **Starling presence scaling model** enables efficient sector-based routing and
effortless scaling to **trillions of devices and IoT nodes**
* ⛓️ **Novel Consensus (PoCW)** - Ixian's **custom Proof of Collaborative Work** rewards distributed validation through
multi-signer consensus, combining **security, fairness, and energy efficiency**
* ♻️ **Resilience by Design** - Fully decentralized, fault-tolerant networking with no downtime or single points of failure
* 🌍 **Human-Friendly Identities (IXI Names)** - Register and use names like 'alice.ixi' to map to Ixian addresses, IPs, or
metadata - decentralized and trustless, like DNS without central authorities

---

## 🧩 Features of Ixian Core

Ixian Core provides reusable primitives and libraries for building dApps and infrastructure across the Ixian Platform:

* **Client Discovery (Ixian Presence System)**

  * Lookup by **cryptographic address**, not IP or DNS
  * Signed presence packets with timestamps + contact endpoints
  * Expiry + keep-alive cycle ensures accurate, fresh status
  * Backed by Ixian's **sector-based model (Starling)** for massive scalability

* **IXI Names**

  * Register human-friendly names (e.g., 'alice.ixi') for a chosen duration (like domain names)
  * Attach metadata such as Ixian addresses, IPs, service endpoints
  * Fully decentralized, no central registry

* **Wallets & Addresses**

  * IXI wallet generation and management
  * Address derivation and utilities

* **Transactions & Blocks**

  * Transaction creation, validation, and inclusion logic
  * Block structures, headers, and signatures
  * Primitives for Ixian's **Proof of Collaborative Work (PoCW)** consensus

    * Core provides hashing, signatures, and PoW validation tools

* **Cryptography**

  * AES and ChaCha20-Poly1305 dual encryption
  * Hybrid key exchange: RSA, ECDH, ML-KEM (**PQC/post-quantum ready**)
  * Hashing, key derivation, Base58 encoding

* **Networking**

  * Ixian P2P protocol primitives
  * Peer discovery and sector/relay architecture
  * JSON REST server for integration

* **Streaming & Messaging**

  * Encrypted messaging and streaming session support
  * Offline push messages
  * Building blocks for S2's **presence-based communication layer**

* **Utilities**

  * Logging and monitoring
  * Platform-specific helpers (Windows/Linux/Mobile)
  * Time synchronization

---

## 📚 Documentation

* Developer Documentation: [https://docs.ixian.io](https://docs.ixian.io)

---

## 🔗 Related Repositories & Examples

* [Ixian-Core](https://github.com/ixian-platform/Ixian-Core) - SDK and shared functionality
* [Ixian-DLT](https://github.com/ixian-platform/Ixian-DLT) - Blockchain ledger and consensus layer
* [Ixian-S2](https://github.com/ixian-platform/Ixian-S2) - Peer-to-peer streaming and messaging overlay
* [Spixi](https://github.com/ixian-platform/Spixi) - Secure messenger and wallet app
* [Ixian-LiteWallet](https://github.com/ixian-platform/Ixian-LiteWallet) - Lightweight CLI wallet
* [QuIXI](https://github.com/ixian-platform/QuIXI) - Quick integration toolkit for Ixian Platform

---

## 🌱 Development Branches

* **master** - Stable, production-ready releases
* **development** - Active development, may contain unfinished features

For reproducible builds, always use the latest **release tag** on `master`.

---

## 🤝 Contributing

We welcome contributions from developers, integrators, and builders.

1. Fork this repository
2. Create a feature branch ('feature/my-change')
3. Commit with clear, descriptive messages
4. Open a Pull Request for review

Join the community on **[Discord](https://discord.gg/pdJNVhv)**.

---

## 🌍 Community & Links

* **Website**: [www.ixian.io](https://www.ixian.io)
* **Docs**: [docs.ixian.io](https://docs.ixian.io)
* **Discord**: [discord.gg/pdJNVhv](https://discord.gg/pdJNVhv)
* **Telegram**: [t.me/ixian\_official\_ENG](https://t.me/ixian_official_ENG)
* **Bitcointalk**: [Forum Thread](https://bitcointalk.org/index.php?topic=4631942.0)
* **GitHub**: [ixian-platform](https://www.github.com/ixian-platform)

---

## 📜 License

Licensed under the [MIT License](LICENSE).
