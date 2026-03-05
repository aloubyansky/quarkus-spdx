# Quarkus SPDX

[![Version](https://img.shields.io/maven-central/v/io.quarkiverse.spdx/quarkus-spdx-v2?logo=apache-maven&style=flat-square)](https://central.sonatype.com/artifact/io.quarkiverse.spdx/quarkus-spdx-parent)

Quarkus extensions that generate application SBOM (Software Bill of Materials) following the [SPDX specification](https://spdx.dev/).

Two extensions are provided, one for each major version of the SPDX specification:

- **`quarkus-spdx-v2`** — generates SBOMs following SPDX 2.3, serialized as JSON or Tag-Value
- **`quarkus-spdx-v3`** — generates SBOMs following SPDX 3.0.1, serialized as JSON-LD

## Usage

Add one of the extensions to your project depending on the desired SPDX version.

### SPDX 2.3

```xml
<dependency>
    <groupId>io.quarkiverse.spdx</groupId>
    <artifactId>quarkus-spdx-v2</artifactId>
    <version>${quarkus-spdx.version}</version>
</dependency>
```

### SPDX 3.0.1

```xml
<dependency>
    <groupId>io.quarkiverse.spdx</groupId>
    <artifactId>quarkus-spdx-v3</artifactId>
    <version>${quarkus-spdx.version}</version>
</dependency>
```

## Configuration

Both extensions share the `quarkus.spdx` configuration prefix. Since they are mutually exclusive (use one or the other), there is no conflict.

### quarkus-spdx-v2

| Property | Default | Description |
|----------|---------|-------------|
| `quarkus.spdx.skip` | `false` | Whether to skip SBOM generation |
| `quarkus.spdx.format` | `json` | SBOM file format (`json`, `tag-value`, or `all`) |
| `quarkus.spdx.include-license-text` | `false` | Whether to include the license text in generated SBOMs |

### quarkus-spdx-v3

| Property | Default | Description |
|----------|---------|-------------|
| `quarkus.spdx.skip` | `false` | Whether to skip SBOM generation |

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
