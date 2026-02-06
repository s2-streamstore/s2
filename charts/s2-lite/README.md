# s2-lite Helm Chart

Deploy s2-lite to Kubernetes using the official Helm chart.

## Quick Start

### Install from Helm repository

```bash
# Add the S2 Helm repository
helm repo add s2 https://s2-streamstore.github.io/s2
helm repo update

# Install with default settings (in-memory)
helm install my-s2-lite s2/s2-lite

# Or install with S3 storage
helm install my-s2-lite s2/s2-lite \
  --set objectStorage.enabled=true \
  --set objectStorage.bucket=my-s3-bucket
```

### Install from OCI registry (GHCR)

```bash
# Install directly from GitHub Container Registry
helm install my-s2-lite oci://ghcr.io/s2-streamstore/charts/s2-lite

# Or with custom values
helm install my-s2-lite oci://ghcr.io/s2-streamstore/charts/s2-lite \
  --set objectStorage.enabled=true \
  --set objectStorage.bucket=my-s3-bucket \
  --set objectStorage.endpoint=https://s3.amazonaws.com
```

## Storage Options

### In-memory (default)

```bash
helm install my-s2-lite s2/s2-lite
```

Great for development and testing. Data is lost when the pod restarts.

### S3-compatible object storage

```bash
helm install my-s2-lite s2/s2-lite \
  --set objectStorage.enabled=true \
  --set objectStorage.bucket=my-bucket \
  --set objectStorage.endpoint=https://s3.amazonaws.com
```

Supports AWS S3, MinIO, Tigris, Cloudflare R2, and other S3-compatible services.

### Local storage with PersistentVolumeClaim

```bash
helm install my-s2-lite s2/s2-lite \
  --set localStorage.enabled=true \
  --set localStorage.persistentVolumeClaim.enabled=true \
  --set localStorage.persistentVolumeClaim.size=10Gi
```

Data persists across pod restarts using PersistentVolumes.

### TLS with self-signed certificates

```bash
helm install my-s2-lite s2/s2-lite \
  --set tls.enabled=true

# Configure CLI to trust self-signed certs
s2 config set ssl_no_verify true
```

Useful for development and testing. For production, use an Ingress with proper TLS termination.

## Configuration

For all configuration options, see the [values.yaml](values.yaml) file.

Common configurations:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/s2-streamstore/s2` |
| `image.tag` | Image tag (defaults to chart appVersion) | `""` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `80` |
| `service.targetPort` | Container port | `8080` |
| `tls.enabled` | Enable self-signed TLS | `false` |
| `objectStorage.enabled` | Enable S3-compatible storage | `false` |
| `objectStorage.bucket` | S3 bucket name | `""` |
| `localStorage.enabled` | Enable local disk storage | `false` |
| `serviceMonitor.enabled` | Enable Prometheus ServiceMonitor | `false` |

## Examples

### AWS S3 with IAM role (IRSA)

```yaml
# values.yaml
objectStorage:
  enabled: true
  bucket: my-s3-bucket

serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/s2-lite-role
```

```bash
helm install my-s2-lite s2/s2-lite -f values.yaml
```

### Behind AWS Network Load Balancer

```yaml
# values.yaml
service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    external-dns.alpha.kubernetes.io/hostname: "s2.example.com"
```

### With Prometheus monitoring

```yaml
# values.yaml
serviceMonitor:
  enabled: true
  interval: 30s
```

## Upgrading

```bash
# Update the repository
helm repo update

# Upgrade to the latest version
helm upgrade my-s2-lite s2/s2-lite

# Or specify a version
helm upgrade my-s2-lite s2/s2-lite --version 0.1.0
```

## Uninstalling

```bash
helm uninstall my-s2-lite
```

Note: PersistentVolumeClaims are not automatically deleted. Delete them manually if needed:

```bash
kubectl delete pvc -l app.kubernetes.io/name=s2-lite
```
