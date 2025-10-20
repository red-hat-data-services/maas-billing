# # ODH - Models as a Service with Policy Management

Our goal is to create a comprehensive platform for **Models as a Service** with real-time policy management.

> [!IMPORTANT]
> This project is a work in progress and is not yet ready for production.

## 📦 Technology Stack

- **OpenShift**: Kubernetes platform
- **Gateway API**: Traffic routing and management (OpenShift native implementation)
- **Kuadrant/Authorino/Limitador**: API gateway and policy engine
- **KServe**: Model serving platform
- **React**: Frontend framework
- **Go**: Backend frameworks

## 📋 Prerequisites

- **Openshift cluster** (4.19.9+) with kubectl/oc access

## 🚀 Quick Start

### Deploy Infrastructure

See the comprehensive [Deployment Guide](deployment/README.md) for detailed instructions.

## 📚 Documentation

- [Deployment Guide](deployment/README.md) - Complete deployment instructions
- [MaaS API Documentation](maas-api/README.md) - Go API for key management
- [OAuth Setup Guide](docs/OAUTH_SETUP.md) - Configure OAuth authentication

Online Documentation: [https://opendatahub-io.github.io/maas-billing/](https://opendatahub-io.github.io/maas-billing/)

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

This project is licensed under the Apache 2.0 License.

## 📞 Support

For questions or issues:
- Open an issue on GitHub
- Check the [deployment guide](deployment/README.md) for troubleshooting
- Review the [samples](docs/samples/models) for examples
