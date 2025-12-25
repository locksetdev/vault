# Lockset Vault

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Lockset Vault is a secure and reliable service for managing secrets. It provides a robust API for creating, retrieving,
and managing secrets and their versions, with a focus on security and performance.

## Features

- **Secure Secret Management**: Store and retrieve secrets with confidence.
- **Versioning**: Keep track of secret versions with tags.
- **Connection Management**: Manage vault connections securely.
- **Authentication**: Protect your vault with public key authentication.
- **Asynchronous API**: Built with Axum for high-performance, non-blocking I/O.
- **Data Persistence**: Uses PostgreSQL for reliable data storage.
- **Encryption**: Leverages AWS KMS for key management and data encryption.

## Configuration

The application is configured using environment variables. The following variables are required:

| Variable          | Description                                        |
|-------------------|----------------------------------------------------|
| `DB_URI`          | The connection string for the PostgreSQL database. |
| `AUTH_PUBLIC_KEY` | The public key used for authenticating requests.   |
| `PORT`            | The port on which the application will listen.     |

## API Endpoints

### Secrets

- `POST /v1/secrets`: Create a new secret.
- `GET /v1/secrets/{name}`: Retrieve the latest version of a secret.
- `POST /v1/secrets/{name}/versions`: Create a new version of a secret.
- `GET /v1/secrets/{name}/versions/{tag}`: Retrieve a specific version of a secret by tag.

### Vault Connections

- `POST /v1/vault-connections`: Create a new vault connection.
- `GET /v1/vault-connections/{public_id}`: Retrieve a vault connection.
- `PATCH /v1/vault-connections/{public_id}`: Update a vault connection.
- `DELETE /v1/vault-connections/{public_id}`: Delete a vault connection.

## Getting Started

#### TBA: Instructions for setting up with Docker

### Prerequisites

- Rust
- PostgreSQL
- AWS Account with KMS configured

### Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/your-username/lockset-vault.git
   cd lockset-vault
   ```

2. Set up the environment variables:
   ```sh
   export DB_URI="postgres://user:password@localhost/yourdb"
   export AUTH_PUBLIC_KEY="your-public-key"
   export PORT="8080"
   ```

3. Run the database migrations:
   ```sh
   sqlx migrate run
   ```

4. Run the application:
   ```sh
   cargo run
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

