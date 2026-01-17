# go-httpclient Examples

This directory contains practical examples demonstrating different authentication modes and features of the `go-httpclient` package.

## Examples Overview

| Example                                           | Description                   | Key Features                                   |
| ------------------------------------------------- | ----------------------------- | ---------------------------------------------- |
| [01-simple-auth](01-simple-auth/)                 | Simple API Key Authentication | Basic API secret in header, easy setup         |
| [02-hmac-auth](02-hmac-auth/)                     | HMAC Signature Authentication | Cryptographic signatures, replay protection    |
| [03-custom-headers](03-custom-headers/)           | Custom Header Names           | Customize header names for compatibility       |
| [04-server-verification](04-server-verification/) | Server-Side Verification      | Complete server with authentication middleware |

## Quick Start

Each example is self-contained and can be run independently:

```bash
cd _example/01-simple-auth
go run main.go
```

## Prerequisites

Make sure you have the `go-httpclient` module available:

```bash
# From the project root directory
go mod download
```

## Example Structure

Each example directory contains:

- `main.go` - Runnable example code
- `README.md` - Detailed documentation and explanation

## Authentication Modes Comparison

| Feature              | Simple Mode        | HMAC Mode              |
| -------------------- | ------------------ | ---------------------- |
| Security Level       | Low                | High                   |
| Setup Complexity     | Very Easy          | Easy                   |
| Replay Protection    | ❌ No              | ✅ Yes (timestamp)     |
| Tampering Protection | ❌ No              | ✅ Yes (signature)     |
| Secret Transmission  | ✅ Yes (in header) | ❌ No (only signature) |
| Use Case             | Internal APIs      | Public APIs            |
| Network Requirement  | HTTPS Required     | HTTPS Recommended      |

## Common Use Cases

### Simple Mode

- Internal microservices communication
- Development and testing environments
- Trusted network environments
- Quick prototyping

### HMAC Mode

- Public-facing APIs
- Third-party integrations
- High-security requirements
- Financial or sensitive data APIs
- Preventing man-in-the-middle attacks

## Learning Path

We recommend going through the examples in order:

1. **Start with 01-simple-auth** - Understand basic authentication
2. **Move to 02-hmac-auth** - Learn cryptographic signatures
3. **Try 03-custom-headers** - Customize for your needs
4. **Study 04-server-verification** - Implement server-side protection

## Additional Resources

- [Main README](../README.md) - Package overview and API documentation
- [auth.go](../auth.go) - Source code implementation
- [auth_test.go](../auth_test.go) - Comprehensive test cases

## Getting Help

If you encounter issues or have questions:

1. Check the example README files for detailed explanations
2. Review the test cases in `auth_test.go` for more usage patterns
3. Open an issue on the GitHub repository

## Contributing

Found a bug or want to add more examples? Contributions are welcome! Please:

1. Follow the existing example structure
2. Include comprehensive README documentation
3. Add comments explaining key concepts
4. Test your examples thoroughly

## License

These examples are part of the go-httpclient project and follow the same MIT License.
