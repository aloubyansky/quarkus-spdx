# Quarkus SPDX

[![Version](https://img.shields.io/maven-central/v/io.quarkiverse.spdx/quarkus-spdx?logo=apache-maven&style=flat-square)](https://central.sonatype.com/artifact/io.quarkiverse.spdx/quarkus-spdx-parent)

A Quarkus extension that generates application SBOM (Software Bill of Materials) following the [SPDX specification](https://spdx.dev/).

## Usage

Add the extension to your project:

```xml
<dependency>
    <groupId>io.quarkiverse.spdx</groupId>
    <artifactId>quarkus-spdx</artifactId>
    <version>${quarkus-spdx.version}</version>
</dependency>
```

## Configuration

The following configuration properties are available:

| Property | Default | Description |
|----------|---------|-------------|
| `quarkus.spdx.skip` | `false` | Whether to skip SBOM generation |
| `quarkus.spdx.format` | `json` | SBOM file format (`json`, `tag-value`, or `all`) |
| `quarkus.spdx.schema-version` | `SPDX-2.3` | SPDX specification version |
| `quarkus.spdx.include-license-text` | `false` | Whether to include the license text in generated SBOMs |

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
