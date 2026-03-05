package io.quarkiverse.spdx.generator.common;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jboss.logging.Logger;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.SpdxModelFactory;

import io.quarkus.bootstrap.app.SbomResult;
import io.quarkus.bootstrap.resolver.maven.EffectiveModelResolver;
import io.quarkus.maven.dependency.ArtifactCoords;
import io.quarkus.sbom.ApplicationComponent;
import io.quarkus.sbom.ApplicationManifest;

public abstract class AbstractSpdxSbomGenerator {

    private static final Logger log = Logger.getLogger(AbstractSpdxSbomGenerator.class);

    protected static final String CLASSIFIER_SPDX = "spdx";

    protected static final Comparator<ArtifactCoords> ARTIFACT_COORDS_COMPARATOR = (c1, c2) -> {
        var i = c1.getGroupId().compareTo(c2.getGroupId());
        if (i != 0) {
            return i;
        }
        i = c1.getArtifactId().compareTo(c2.getArtifactId());
        if (i != 0) {
            return i;
        }
        i = c1.getVersion().compareTo(c2.getVersion());
        if (i != 0) {
            return i;
        }
        i = c1.getClassifier().compareTo(c2.getClassifier());
        if (i != 0) {
            return i;
        }
        return c1.getType().compareTo(c2.getType());
    };

    private boolean generated;
    private ApplicationManifest manifest;
    private Path outputDir;
    private Path outputFile;
    private EffectiveModelResolver modelResolver;
    protected final Map<String, String> componentToSpdxId = new HashMap<>();
    protected int spdxIdCounter;

    protected ApplicationManifest getManifest() {
        return manifest;
    }

    protected Path getOutputDir() {
        return outputDir;
    }

    protected Path getConfiguredOutputFile() {
        return outputFile;
    }

    protected EffectiveModelResolver getModelResolver() {
        return modelResolver;
    }

    protected void setManifestInternal(ApplicationManifest manifest) {
        ensureNotGenerated();
        this.manifest = manifest;
    }

    protected void setOutputDirectoryInternal(Path outputDir) {
        ensureNotGenerated();
        this.outputDir = outputDir;
    }

    protected void setOutputFileInternal(Path outputFile) {
        ensureNotGenerated();
        this.outputFile = outputFile;
    }

    protected void setEffectiveModelResolverInternal(EffectiveModelResolver modelResolver) {
        ensureNotGenerated();
        this.modelResolver = modelResolver;
    }

    public List<SbomResult> generate() {
        ensureNotGenerated();
        Objects.requireNonNull(manifest, "Manifest is null");
        if (outputFile == null && outputDir == null) {
            throw new IllegalArgumentException("Either outputDir or outputFile must be provided");
        }
        generated = true;

        try {
            SpdxModelFactory.init();
            return doGenerate();
        } catch (InvalidSPDXAnalysisException e) {
            throw new RuntimeException("Failed to generate SPDX SBOM", e);
        }
    }

    protected abstract List<SbomResult> doGenerate() throws InvalidSPDXAnalysisException;

    protected String generateSpdxId(ApplicationComponent component) {
        var dep = component.getResolvedDependency();
        String key;
        if (dep != null) {
            key = dep.getGroupId() + ":" + dep.getArtifactId() + ":" + dep.getVersion();
        } else if (component.getDistributionPath() != null) {
            key = component.getDistributionPath();
        } else if (component.getPath() != null) {
            key = component.getPath().toString();
        } else {
            key = "component-" + (++spdxIdCounter);
        }

        String spdxId = "SPDXRef-Package-" + sanitizeForSpdxId(key);
        componentToSpdxId.put(key, spdxId);
        return spdxId;
    }

    protected String getComponentKey(ApplicationComponent component) {
        var dep = component.getResolvedDependency();
        if (dep != null) {
            return dep.getGroupId() + ":" + dep.getArtifactId() + ":" + dep.getVersion();
        } else if (component.getDistributionPath() != null) {
            return component.getDistributionPath();
        } else if (component.getPath() != null) {
            return component.getPath().toString();
        }
        return null;
    }

    protected String sanitizeForSpdxId(String input) {
        return input.replaceAll("[^a-zA-Z0-9.-]", "-");
    }

    protected String getComponentName(ApplicationComponent component) {
        var dep = component.getResolvedDependency();
        if (dep != null) {
            return dep.getArtifactId();
        }
        if (component.getPath() != null) {
            return stripExtension(component.getPath().getFileName().toString());
        }
        return "application";
    }

    protected String getMavenDownloadLocation(ArtifactCoords coords) {
        return String.format("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.%s",
                coords.getGroupId().replace('.', '/'),
                coords.getArtifactId(),
                coords.getVersion(),
                coords.getArtifactId(),
                coords.getVersion(),
                coords.getType());
    }

    protected String buildPurl(ArtifactCoords coords) {
        StringBuilder purl = new StringBuilder();
        purl.append("pkg:maven/")
                .append(coords.getGroupId())
                .append("/")
                .append(coords.getArtifactId())
                .append("@")
                .append(coords.getVersion());

        String classifier = coords.getClassifier();
        if (classifier != null && !classifier.isEmpty()) {
            purl.append("?classifier=").append(classifier)
                    .append("&type=").append(coords.getType());
        } else {
            purl.append("?type=").append(coords.getType());
        }
        return purl.toString();
    }

    protected ComponentInfo resolveComponentInfo(ApplicationComponent component) {
        var dep = component.getResolvedDependency();
        var info = new ComponentInfo();
        if (dep != null) {
            info.name = dep.getGroupId() + ":" + dep.getArtifactId();
            info.version = dep.getVersion();
            info.downloadLocation = getMavenDownloadLocation(dep);
        } else if (component.getDistributionPath() != null) {
            String distPath = component.getDistributionPath();
            int lastSlash = distPath.lastIndexOf('/');
            info.name = lastSlash >= 0 ? distPath.substring(lastSlash + 1) : distPath;
        } else if (component.getPath() != null) {
            info.name = component.getPath().getFileName().toString();
        } else {
            throw new RuntimeException("Component is not associated with any file system path");
        }
        return info;
    }

    protected String calculateHash(byte[] data, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(data);
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + algorithm, e);
        }
    }

    protected static List<ArtifactCoords> sortAlphabetically(Collection<ArtifactCoords> col) {
        var list = new ArrayList<>(col);
        list.sort(ARTIFACT_COORDS_COMPARATOR);
        return list;
    }

    protected static String stripExtension(String fileName) {
        var lastDot = fileName.lastIndexOf('.');
        if (lastDot <= 0) {
            return fileName;
        }
        var lastDash = fileName.lastIndexOf('-');
        return lastDot < lastDash ? fileName : fileName.substring(0, lastDot);
    }

    protected String createTimestamp() {
        return ZonedDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));
    }

    protected SbomResult persistSbom(Path sbomFile, String spdxVersion, String format,
            SerializeAction serializeAction) {
        var outDir = sbomFile.getParent();
        if (outDir != null) {
            try {
                Files.createDirectories(outDir);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        try (var outputStream = Files.newOutputStream(sbomFile)) {
            serializeAction.serialize(outputStream);
            if (log.isDebugEnabled()) {
                log.debug("Generated SPDX SBOM at: " + sbomFile);
            }
        } catch (IOException | InvalidSPDXAnalysisException e) {
            throw new RuntimeException("Failed to write SPDX SBOM to " + sbomFile, e);
        }

        return new SbomResult(sbomFile, "SPDX", spdxVersion, format, CLASSIFIER_SPDX,
                manifest.getRunnerPath());
    }

    protected String mapToSpdxLicenseId(String licenseName) {
        if (licenseName == null) {
            return "NOASSERTION";
        }
        String normalized = licenseName.toLowerCase().trim();

        if (normalized.contains("apache") && normalized.contains("2")) {
            return "Apache-2.0";
        }
        if (normalized.contains("mit")) {
            return "MIT";
        }
        if (normalized.contains("edl") || normalized.contains("eclipse distribution")) {
            return "BSD-3-Clause";
        }
        if (normalized.contains("bsd") && normalized.contains("3")) {
            return "BSD-3-Clause";
        }
        if (normalized.contains("bsd") && normalized.contains("2")) {
            return "BSD-2-Clause";
        }
        boolean isGpl = normalized.contains("gpl") || normalized.contains("general public license");
        boolean isLgpl = normalized.contains("lgpl") || normalized.contains("lesser general public");

        if (isGpl && normalized.contains("classpath")) {
            return "GPL-2.0-only WITH Classpath-exception-2.0";
        }
        if (isLgpl && normalized.contains("2.1")) {
            return "LGPL-2.1-only";
        }
        if (isLgpl && normalized.contains("3")) {
            return "LGPL-3.0-only";
        }
        if (isGpl && normalized.contains("2")) {
            return "GPL-2.0-only";
        }
        if (isGpl && normalized.contains("3")) {
            return "GPL-3.0-only";
        }
        if ((normalized.contains("eclipse") || normalized.contains("epl")) && normalized.contains("1.0")) {
            return "EPL-1.0";
        }
        if ((normalized.contains("eclipse") || normalized.contains("epl")) &&
                (normalized.contains("2.0") || normalized.contains("2 "))) {
            return "EPL-2.0";
        }
        if (normalized.contains("universal permissive") || normalized.contains("upl")) {
            return "UPL-1.0";
        }
        if (normalized.contains("mpl") && normalized.contains("2")) {
            return "MPL-2.0";
        }
        if (normalized.contains("cc0") || normalized.equals("public domain")) {
            return "CC0-1.0";
        }

        return licenseName;
    }

    protected void ensureNotGenerated() {
        if (generated) {
            throw new RuntimeException("This instance has already been used to generate an SBOM");
        }
    }

    public static class ComponentInfo {
        public String name;
        public String version = "";
        public String downloadLocation = "NOASSERTION";
    }

    @FunctionalInterface
    public interface SerializeAction {
        void serialize(OutputStream outputStream) throws IOException, InvalidSPDXAnalysisException;
    }
}
