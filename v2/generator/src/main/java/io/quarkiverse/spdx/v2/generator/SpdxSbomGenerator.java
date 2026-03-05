package io.quarkiverse.spdx.v2.generator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.maven.model.Model;
import org.jboss.logging.Logger;
import org.spdx.core.DefaultModelStore;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.jacksonstore.MultiFormatStore;
import org.spdx.jacksonstore.MultiFormatStore.Format;
import org.spdx.library.LicenseInfoFactory;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.v2.Annotation;
import org.spdx.library.model.v2.Checksum;
import org.spdx.library.model.v2.ExternalRef;
import org.spdx.library.model.v2.ReferenceType;
import org.spdx.library.model.v2.Relationship;
import org.spdx.library.model.v2.SpdxCreatorInformation;
import org.spdx.library.model.v2.SpdxDocument;
import org.spdx.library.model.v2.SpdxPackage;
import org.spdx.library.model.v2.enumerations.AnnotationType;
import org.spdx.library.model.v2.enumerations.ChecksumAlgorithm;
import org.spdx.library.model.v2.enumerations.ReferenceCategory;
import org.spdx.library.model.v2.enumerations.RelationshipType;
import org.spdx.library.model.v2.license.AnyLicenseInfo;
import org.spdx.library.model.v2.license.SpdxNoAssertionLicense;
import org.spdx.storage.IModelStore;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.tagvaluestore.TagValueStore;

import io.quarkiverse.spdx.generator.common.AbstractSpdxSbomGenerator;
import io.quarkus.bootstrap.app.SbomResult;
import io.quarkus.bootstrap.resolver.maven.EffectiveModelResolver;
import io.quarkus.maven.dependency.ArtifactCoords;
import io.quarkus.sbom.ApplicationComponent;
import io.quarkus.sbom.ApplicationManifest;

public class SpdxSbomGenerator extends AbstractSpdxSbomGenerator {

    private static final Logger log = Logger.getLogger(SpdxSbomGenerator.class);

    private static final String SPDX_VERSION = "SPDX-2.3";
    private static final String DATA_LICENSE = "CC0-1.0";

    private static final String FORMAT_ALL = "all";
    private static final String FORMAT_JSON = "json";
    private static final String FORMAT_TAG_VALUE = "tag-value";
    private static final String DEFAULT_FORMAT = FORMAT_JSON;
    private static final List<String> SUPPORTED_FORMATS = List.of(FORMAT_JSON, FORMAT_TAG_VALUE);

    public static SpdxSbomGenerator newInstance() {
        return new SpdxSbomGenerator();
    }

    private String format;
    private boolean includeLicenseText;

    private IModelStore modelStore;
    private ModelCopyManager copyManager;
    private String documentUri;
    private String creationTimestamp;

    private SpdxSbomGenerator() {
    }

    public SpdxSbomGenerator setManifest(ApplicationManifest manifest) {
        setManifestInternal(manifest);
        return this;
    }

    public SpdxSbomGenerator setOutputDirectory(Path outputDir) {
        setOutputDirectoryInternal(outputDir);
        return this;
    }

    public SpdxSbomGenerator setOutputFile(Path outputFile) {
        setOutputFileInternal(outputFile);
        return this;
    }

    public SpdxSbomGenerator setFormat(String format) {
        ensureNotGenerated();
        this.format = format;
        return this;
    }

    public SpdxSbomGenerator setEffectiveModelResolver(EffectiveModelResolver modelResolver) {
        setEffectiveModelResolverInternal(modelResolver);
        return this;
    }

    public SpdxSbomGenerator setIncludeLicenseText(boolean includeLicenseText) {
        ensureNotGenerated();
        this.includeLicenseText = includeLicenseText;
        return this;
    }

    @Override
    protected List<SbomResult> doGenerate() throws InvalidSPDXAnalysisException {
        if (FORMAT_ALL.equalsIgnoreCase(format)) {
            if (getConfiguredOutputFile() != null) {
                throw new IllegalArgumentException("Can't use output file " + getConfiguredOutputFile() + " with format '"
                        + FORMAT_ALL + "', since it implies generating multiple files");
            }
            final List<SbomResult> result = new ArrayList<>(SUPPORTED_FORMATS.size());
            for (String fmt : SUPPORTED_FORMATS) {
                result.add(generateForFormat(fmt, getOutputFile(fmt)));
            }
            return result;
        }
        var outFile = getOutputFile(format == null ? DEFAULT_FORMAT : format);
        return List.of(generateForFormat(getFormat(outFile), outFile));
    }

    private SbomResult generateForFormat(String format, Path sbomFile) throws InvalidSPDXAnalysisException {
        ISerializableModelStore serializableStore;
        if (format.equalsIgnoreCase(FORMAT_JSON)) {
            serializableStore = new MultiFormatStore(new InMemSpdxStore(), Format.JSON_PRETTY);
        } else if (format.equalsIgnoreCase(FORMAT_TAG_VALUE)) {
            serializableStore = new TagValueStore(new InMemSpdxStore());
        } else {
            throw new RuntimeException(
                    "Unsupported SBOM format " + format + ", supported formats are json and tag-value");
        }

        modelStore = serializableStore;
        copyManager = new ModelCopyManager();
        componentToSpdxId.clear();
        spdxIdCounter = 0;

        var mainComponent = getManifest().getMainComponent();
        String appName = getComponentName(mainComponent);
        documentUri = "https://spdx.org/spdxdocs/" + appName + "-" + System.currentTimeMillis();

        DefaultModelStore.initialize(modelStore, documentUri, copyManager);

        var document = createSpdxDocument(appName);

        var mainPackage = createPackage(mainComponent, true);
        document.getDocumentDescribes().add(mainPackage);

        for (var component : getManifest().getComponents()) {
            var pkg = createPackage(component, false);
            document.getDocumentDescribes().add(pkg);
        }

        addRelationships(document, mainComponent, getManifest().getComponents());

        return persistSbom(sbomFile, SPDX_VERSION, format,
                outputStream -> serializableStore.serialize(outputStream));
    }

    private SpdxDocument createSpdxDocument(String name) throws InvalidSPDXAnalysisException {
        var creationInfo = new SpdxCreatorInformation(
                modelStore, documentUri, modelStore.getNextId(IModelStore.IdType.Anonymous),
                copyManager, true);
        creationInfo.getCreators().add("Tool: Quarkus SPDX Generator");
        creationTimestamp = createTimestamp();
        creationInfo.setCreated(creationTimestamp);

        var document = new SpdxDocument(modelStore, documentUri, copyManager, true);
        document.setSpecVersion(SPDX_VERSION);
        document.setName(name);
        document.setCreationInfo(creationInfo);

        var dataLicense = LicenseInfoFactory.parseSPDXLicenseStringCompatV2(DATA_LICENSE);
        document.setDataLicense(dataLicense);

        return document;
    }

    private SpdxPackage createPackage(ApplicationComponent component, boolean isMain) throws InvalidSPDXAnalysisException {
        String spdxId = generateSpdxId(component);
        var dep = component.getResolvedDependency();
        var info = resolveComponentInfo(component);

        var pkg = new SpdxPackage(modelStore, documentUri, spdxId, copyManager, true);
        pkg.setName(info.name);
        if (!info.version.isEmpty()) {
            pkg.setVersionInfo(info.version);
        }
        pkg.setDownloadLocation(info.downloadLocation);
        pkg.setFilesAnalyzed(false);

        AnyLicenseInfo concludedLicense = new SpdxNoAssertionLicense();
        AnyLicenseInfo declaredLicense = new SpdxNoAssertionLicense();

        if (dep != null) {
            var model = getModelResolver() == null ? null : getModelResolver().resolveEffectiveModel(dep);
            if (model != null) {
                extractPackageMetadata(model, pkg);
                declaredLicense = extractLicense(model);
            }
        }

        pkg.setLicenseConcluded(concludedLicense);
        pkg.setLicenseDeclared(declaredLicense);
        pkg.setCopyrightText("NOASSERTION");

        if (component.getPath() != null && Files.exists(component.getPath())) {
            addChecksums(pkg, component.getPath());
        }

        if (component.getDistributionPath() != null) {
            pkg.setComment("Distribution path: " + component.getDistributionPath());
        }

        if (dep != null) {
            addPurlExternalRef(pkg, dep);
        }

        addScopeAnnotation(pkg, component.getScope());

        return pkg;
    }

    private void addPurlExternalRef(SpdxPackage pkg, ArtifactCoords coords) throws InvalidSPDXAnalysisException {
        var externalRef = new ExternalRef(modelStore, documentUri,
                modelStore.getNextId(IModelStore.IdType.Anonymous), copyManager, true);
        externalRef.setReferenceCategory(ReferenceCategory.PACKAGE_MANAGER);
        externalRef.setReferenceType(new ReferenceType("http://spdx.org/rdf/references/purl"));
        externalRef.setReferenceLocator(buildPurl(coords));
        pkg.addExternalRef(externalRef);
    }

    private void addScopeAnnotation(SpdxPackage pkg, String scope) throws InvalidSPDXAnalysisException {
        var annotation = new Annotation(modelStore, documentUri,
                modelStore.getNextId(IModelStore.IdType.Anonymous), copyManager, true);
        annotation.setAnnotationType(AnnotationType.OTHER);
        annotation.setAnnotator("Tool: Quarkus SPDX Generator");
        annotation.setAnnotationDate(creationTimestamp);
        annotation.setComment("quarkus:component:scope=" + scope);
        pkg.getAnnotations().add(annotation);
    }

    private void extractPackageMetadata(Model model, SpdxPackage pkg) throws InvalidSPDXAnalysisException {
        if (model.getDescription() != null) {
            pkg.setDescription(model.getDescription());
        }
        if (model.getOrganization() != null && model.getOrganization().getName() != null) {
            pkg.setSupplier("Organization: " + model.getOrganization().getName());
        }
        if (model.getUrl() != null) {
            pkg.setHomepage(model.getUrl());
        }
    }

    private AnyLicenseInfo extractLicense(Model model) throws InvalidSPDXAnalysisException {
        if (model.getLicenses() == null || model.getLicenses().isEmpty()) {
            return new SpdxNoAssertionLicense();
        }

        var license = model.getLicenses().get(0);
        String licenseName = license.getName();
        if (licenseName == null || licenseName.trim().isEmpty()) {
            return new SpdxNoAssertionLicense();
        }

        try {
            return LicenseInfoFactory.parseSPDXLicenseStringCompatV2(mapToSpdxLicenseId(licenseName));
        } catch (InvalidSPDXAnalysisException e) {
            log.debugf("Could not parse license '%s' as SPDX license, using NOASSERTION", licenseName);
            return new SpdxNoAssertionLicense();
        }
    }

    private void addChecksums(SpdxPackage pkg, Path filePath) throws InvalidSPDXAnalysisException {
        try {
            byte[] fileBytes = Files.readAllBytes(filePath);

            addChecksum(pkg, fileBytes, "MD5", ChecksumAlgorithm.MD5);
            addChecksum(pkg, fileBytes, "SHA-1", ChecksumAlgorithm.SHA1);
            addChecksum(pkg, fileBytes, "SHA-256", ChecksumAlgorithm.SHA256);
            addChecksum(pkg, fileBytes, "SHA-512", ChecksumAlgorithm.SHA512);
            addChecksum(pkg, fileBytes, "SHA3-256", ChecksumAlgorithm.SHA3_256);
            addChecksum(pkg, fileBytes, "SHA3-512", ChecksumAlgorithm.SHA3_512);
            addChecksum(pkg, fileBytes, "SHA-384", ChecksumAlgorithm.SHA384);
            addChecksum(pkg, fileBytes, "SHA3-384", ChecksumAlgorithm.SHA3_384);

        } catch (IOException e) {
            log.warnf("Failed to calculate checksums for %s: %s", filePath, e.getMessage());
        }
    }

    private void addChecksum(SpdxPackage pkg, byte[] data, String algorithm, ChecksumAlgorithm spdxAlgorithm)
            throws InvalidSPDXAnalysisException {
        String hashValue = calculateHash(data, algorithm);
        var checksum = new Checksum(modelStore, documentUri,
                modelStore.getNextId(IModelStore.IdType.Anonymous), copyManager, true);
        checksum.setAlgorithm(spdxAlgorithm);
        checksum.setValue(hashValue);
        pkg.getChecksums().add(checksum);
    }

    private void addRelationships(SpdxDocument document, ApplicationComponent mainComponent,
            Collection<ApplicationComponent> components) throws InvalidSPDXAnalysisException {

        addDependencyRelationships(mainComponent);
        for (var comp : components) {
            addDependencyRelationships(comp);
        }
    }

    private void addDependencyRelationships(ApplicationComponent component) throws InvalidSPDXAnalysisException {
        var dependencies = component.getDependencies();
        if (dependencies == null || dependencies.isEmpty()) {
            return;
        }

        String sourceSpdxId = componentToSpdxId.get(getComponentKey(component));
        if (sourceSpdxId == null) {
            return;
        }

        var sourceElement = new SpdxPackage(modelStore, documentUri, sourceSpdxId, copyManager, false);

        for (var depCoords : sortAlphabetically(dependencies)) {
            String depKey = depCoords.getGroupId() + ":" + depCoords.getArtifactId() + ":" + depCoords.getVersion();
            String targetSpdxId = componentToSpdxId.get(depKey);
            if (targetSpdxId == null) {
                continue;
            }

            var targetElement = new SpdxPackage(modelStore, documentUri, targetSpdxId, copyManager, false);

            var relationship = new Relationship(modelStore, documentUri,
                    modelStore.getNextId(IModelStore.IdType.Anonymous), copyManager, true);
            relationship.setRelatedSpdxElement(targetElement);
            relationship.setRelationshipType(RelationshipType.DEPENDS_ON);
            sourceElement.getRelationships().add(relationship);
        }
    }

    private Path getOutputFile(String defaultFormat) {
        if (getConfiguredOutputFile() == null) {
            String ext = FORMAT_TAG_VALUE.equals(defaultFormat) ? "spdx" : defaultFormat;
            var fileName = toSbomFileName(getManifest().getRunnerPath().getFileName().toString(), ext);
            return getOutputDir() == null ? Path.of(fileName) : getOutputDir().resolve(fileName);
        }
        return getConfiguredOutputFile();
    }

    private String toSbomFileName(String deliverableName, String extension) {
        return stripExtension(deliverableName) + "-" + CLASSIFIER_SPDX + "." + extension;
    }

    private String getFormat(Path outputFile) {
        if (format == null || FORMAT_ALL.equalsIgnoreCase(format)) {
            var name = outputFile.getFileName().toString();
            var lastDot = name.lastIndexOf('.');
            if (lastDot < 0 || lastDot == name.length() - 1) {
                throw new IllegalArgumentException("Failed to determine file extension of " + outputFile);
            }
            String ext = name.substring(lastDot + 1);
            return "spdx".equals(ext) ? FORMAT_TAG_VALUE : ext;
        }
        return format;
    }
}
