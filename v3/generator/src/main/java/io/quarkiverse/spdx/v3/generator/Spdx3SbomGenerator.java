package io.quarkiverse.spdx.v3.generator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.maven.model.Model;
import org.jboss.logging.Logger;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.v3_0_1.core.Agent;
import org.spdx.library.model.v3_0_1.core.Annotation;
import org.spdx.library.model.v3_0_1.core.AnnotationType;
import org.spdx.library.model.v3_0_1.core.CreationInfo;
import org.spdx.library.model.v3_0_1.core.ExternalIdentifier;
import org.spdx.library.model.v3_0_1.core.ExternalIdentifierType;
import org.spdx.library.model.v3_0_1.core.Hash;
import org.spdx.library.model.v3_0_1.core.HashAlgorithm;
import org.spdx.library.model.v3_0_1.core.ProfileIdentifierType;
import org.spdx.library.model.v3_0_1.core.Relationship;
import org.spdx.library.model.v3_0_1.core.RelationshipType;
import org.spdx.library.model.v3_0_1.core.SpdxDocument;
import org.spdx.library.model.v3_0_1.core.Tool;
import org.spdx.library.model.v3_0_1.simplelicensing.AnyLicenseInfo;
import org.spdx.library.model.v3_0_1.simplelicensing.LicenseExpression;
import org.spdx.library.model.v3_0_1.software.Sbom;
import org.spdx.library.model.v3_0_1.software.SbomType;
import org.spdx.library.model.v3_0_1.software.SpdxPackage;
import org.spdx.storage.IModelStore;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.v3jsonldstore.JsonLDStore;

import io.quarkiverse.spdx.generator.common.AbstractSpdxSbomGenerator;
import io.quarkus.bootstrap.app.SbomResult;
import io.quarkus.bootstrap.resolver.maven.EffectiveModelResolver;
import io.quarkus.maven.dependency.ArtifactCoords;
import io.quarkus.sbom.ApplicationComponent;
import io.quarkus.sbom.ApplicationManifest;

public class Spdx3SbomGenerator extends AbstractSpdxSbomGenerator {

    private static final Logger log = Logger.getLogger(Spdx3SbomGenerator.class);

    private static final String SPDX_3_VERSION = "3.0.1";
    private static final String TOOL_NAME = "Quarkus SPDX Generator";

    public static Spdx3SbomGenerator newInstance() {
        return new Spdx3SbomGenerator();
    }

    private IModelStore modelStore;
    private org.spdx.core.IModelCopyManager copyManager;
    private String documentUri;
    private CreationInfo creationInfo;
    private Tool creatorTool;
    private Agent creatorAgent;
    private final List<Agent> supplierAgents = new ArrayList<>();
    private final List<Relationship> licenseRelationships = new ArrayList<>();
    private final List<AnyLicenseInfo> licenseElements = new ArrayList<>();

    private Spdx3SbomGenerator() {
    }

    public Spdx3SbomGenerator setManifest(ApplicationManifest manifest) {
        setManifestInternal(manifest);
        return this;
    }

    public Spdx3SbomGenerator setOutputDirectory(Path outputDir) {
        setOutputDirectoryInternal(outputDir);
        return this;
    }

    public Spdx3SbomGenerator setOutputFile(Path outputFile) {
        setOutputFileInternal(outputFile);
        return this;
    }

    public Spdx3SbomGenerator setEffectiveModelResolver(EffectiveModelResolver modelResolver) {
        setEffectiveModelResolverInternal(modelResolver);
        return this;
    }

    @Override
    protected List<SbomResult> doGenerate() throws InvalidSPDXAnalysisException {
        Path sbomFile = getOutputFile();
        return List.of(generateJsonLd(sbomFile));
    }

    private SbomResult generateJsonLd(Path sbomFile) throws InvalidSPDXAnalysisException {
        var baseStore = new InMemSpdxStore();
        var jsonLdStore = new JsonLDStore(baseStore, true);

        modelStore = jsonLdStore;
        copyManager = new ModelCopyManager();
        componentToSpdxId.clear();
        spdxIdCounter = 0;
        supplierAgents.clear();
        licenseRelationships.clear();
        licenseElements.clear();

        var mainComponent = getManifest().getMainComponent();
        String appName = getComponentName(mainComponent);
        documentUri = "https://spdx.org/spdxdocs/" + appName + "-" + System.currentTimeMillis();

        creationInfo = createCreationInfo();

        var sbom = createSbom(appName);

        var mainPackage = createPackage(mainComponent);
        sbom.getElements().add(mainPackage);
        sbom.getRootElements().add(mainPackage);

        for (var component : getManifest().getComponents()) {
            var pkg = createPackage(component);
            sbom.getElements().add(pkg);
        }

        addRelationships(sbom, mainComponent, getManifest().getComponents());

        for (var agent : supplierAgents) {
            sbom.getElements().add(agent);
        }
        for (var licenseElement : licenseElements) {
            sbom.getElements().add(licenseElement);
        }
        for (var licenseRel : licenseRelationships) {
            sbom.getElements().add(licenseRel);
        }

        var document = createSpdxDocument(appName);
        document.getRootElements().add(sbom);
        // Add all sbom elements to the document so they are serialized as
        // top-level @graph entries rather than just URI references
        document.getElements().add(sbom);
        document.getElements().add(creatorTool);
        document.getElements().add(creatorAgent);
        for (var element : sbom.getElements()) {
            document.getElements().add(element);
        }

        return persistSbom(sbomFile, SPDX_3_VERSION, "json",
                outputStream -> jsonLdStore.serialize(outputStream, document));
    }

    private CreationInfo createCreationInfo() throws InvalidSPDXAnalysisException {
        var info = new CreationInfo(modelStore, uri("creationInfo"), copyManager, true, null);
        info.setSpecVersion(SPDX_3_VERSION);
        info.setCreated(createTimestamp());

        creatorTool = new Tool(modelStore, uri("tool-quarkus-spdx-generator"), copyManager, true, null);
        creatorTool.setCreationInfo(info);
        creatorTool.setName(TOOL_NAME);
        info.getCreatedUsings().add(creatorTool);

        creatorAgent = new Agent(modelStore, uri("agent-quarkus-spdx-generator"), copyManager, true, null);
        creatorAgent.setCreationInfo(info);
        creatorAgent.setName(TOOL_NAME);
        info.getCreatedBys().add(creatorAgent);

        return info;
    }

    private Sbom createSbom(String name) throws InvalidSPDXAnalysisException {
        var sbom = new Sbom(modelStore, uri("SBOM"), copyManager, true, null);
        sbom.setCreationInfo(creationInfo);
        sbom.setName(name);
        sbom.getSbomTypes().add(SbomType.BUILD);
        sbom.getProfileConformances().add(ProfileIdentifierType.SOFTWARE);
        sbom.getProfileConformances().add(ProfileIdentifierType.CORE);
        sbom.getElements().add(creatorTool);
        sbom.getElements().add(creatorAgent);
        return sbom;
    }

    private SpdxDocument createSpdxDocument(String name) throws InvalidSPDXAnalysisException {
        var document = new SpdxDocument(modelStore, uri("DOCUMENT"), copyManager, true, null);
        document.setCreationInfo(creationInfo);
        document.setName(name);
        document.getProfileConformances().add(ProfileIdentifierType.SOFTWARE);
        document.getProfileConformances().add(ProfileIdentifierType.CORE);
        return document;
    }

    private SpdxPackage createPackage(ApplicationComponent component)
            throws InvalidSPDXAnalysisException {
        String spdxId = generateSpdxId(component);
        var dep = component.getResolvedDependency();
        var info = resolveComponentInfo(component);

        var pkg = new SpdxPackage(modelStore, uri(spdxId), copyManager, true, null);
        pkg.setCreationInfo(creationInfo);
        pkg.setName(info.name);
        if (!info.version.isEmpty()) {
            pkg.setPackageVersion(info.version);
        }
        pkg.setDownloadLocation(info.downloadLocation);
        pkg.setCopyrightText("NOASSERTION");

        if (dep != null) {
            pkg.setPackageUrl(buildPurl(dep));
            addPurlExternalIdentifier(pkg, dep);

            var model = getModelResolver() == null ? null : getModelResolver().resolveEffectiveModel(dep);
            if (model != null) {
                extractPackageMetadata(model, pkg);
                addLicenseRelationships(pkg, model);
            }
        }

        if (component.getPath() != null && Files.exists(component.getPath())) {
            addHashes(pkg, component.getPath());
        }

        if (component.getDistributionPath() != null) {
            pkg.setComment("Distribution path: " + component.getDistributionPath());
        }

        addScopeAnnotation(pkg, component.getScope());

        return pkg;
    }

    private String uri(String localId) {
        return documentUri + "/" + localId;
    }

    private void addPurlExternalIdentifier(SpdxPackage pkg, ArtifactCoords coords)
            throws InvalidSPDXAnalysisException {
        var extId = new ExternalIdentifier(modelStore, uri("extid-" + (++spdxIdCounter)), copyManager, true, null);
        extId.setExternalIdentifierType(ExternalIdentifierType.PACKAGE_URL);
        extId.setIdentifier(buildPurl(coords));
        pkg.getExternalIdentifiers().add(extId);
    }

    private void addScopeAnnotation(SpdxPackage pkg, String scope) throws InvalidSPDXAnalysisException {
        var annotation = new Annotation(modelStore,
                uri("annotation-" + sanitizeForSpdxId(pkg.getName().orElse("unknown")) + "-scope"),
                copyManager, true, null);
        annotation.setCreationInfo(creationInfo);
        annotation.setAnnotationType(AnnotationType.OTHER);
        annotation.setSubject(pkg);
        annotation.setStatement("quarkus:component:scope=" + scope);
    }

    private void extractPackageMetadata(Model model, SpdxPackage pkg) throws InvalidSPDXAnalysisException {
        if (model.getDescription() != null) {
            pkg.setDescription(model.getDescription());
        }
        if (model.getUrl() != null) {
            pkg.setHomePage(model.getUrl());
        }
        if (model.getOrganization() != null && model.getOrganization().getName() != null) {
            var supplier = new Agent(modelStore,
                    uri("agent-" + sanitizeForSpdxId(model.getOrganization().getName())),
                    copyManager, true, null);
            supplier.setCreationInfo(creationInfo);
            supplier.setName(model.getOrganization().getName());
            pkg.setSuppliedBy(supplier);
            supplierAgents.add(supplier);
        }
    }

    private void addLicenseRelationships(SpdxPackage pkg, Model model) throws InvalidSPDXAnalysisException {
        String spdxLicenseId = extractSpdxLicenseId(model);

        if (spdxLicenseId != null) {
            String pkgName = pkg.getName().orElse("unknown");
            var licenseExpr = new LicenseExpression(modelStore,
                    uri("license-" + sanitizeForSpdxId(pkgName) + "-" + (++spdxIdCounter)),
                    copyManager, true, null);
            licenseExpr.setCreationInfo(creationInfo);
            licenseExpr.setLicenseExpression(spdxLicenseId);
            licenseElements.add(licenseExpr);

            var declaredRel = new Relationship(modelStore,
                    uri("rel-declared-license-" + sanitizeForSpdxId(pkgName) + "-" + (++spdxIdCounter)),
                    copyManager, true, null);
            declaredRel.setCreationInfo(creationInfo);
            declaredRel.setFrom(pkg);
            declaredRel.getTos().add(licenseExpr);
            declaredRel.setRelationshipType(RelationshipType.HAS_DECLARED_LICENSE);
            licenseRelationships.add(declaredRel);
        }
    }

    private String extractSpdxLicenseId(Model model) {
        if (model.getLicenses() == null || model.getLicenses().isEmpty()) {
            return null;
        }
        var license = model.getLicenses().get(0);
        String licenseName = license.getName();
        if (licenseName == null || licenseName.trim().isEmpty()) {
            return null;
        }
        return mapToSpdxLicenseId(licenseName);
    }

    private void addHashes(SpdxPackage pkg, Path filePath) throws InvalidSPDXAnalysisException {
        try {
            byte[] fileBytes = Files.readAllBytes(filePath);

            addHash(pkg, fileBytes, "MD5", HashAlgorithm.MD5);
            addHash(pkg, fileBytes, "SHA-1", HashAlgorithm.SHA1);
            addHash(pkg, fileBytes, "SHA-256", HashAlgorithm.SHA256);
            addHash(pkg, fileBytes, "SHA-512", HashAlgorithm.SHA512);
            addHash(pkg, fileBytes, "SHA3-256", HashAlgorithm.SHA3_256);
            addHash(pkg, fileBytes, "SHA3-512", HashAlgorithm.SHA3_512);
            addHash(pkg, fileBytes, "SHA-384", HashAlgorithm.SHA384);
            addHash(pkg, fileBytes, "SHA3-384", HashAlgorithm.SHA3_384);

        } catch (IOException e) {
            log.warnf("Failed to calculate hashes for %s: %s", filePath, e.getMessage());
        }
    }

    private void addHash(SpdxPackage pkg, byte[] data, String algorithm, HashAlgorithm spdxAlgorithm)
            throws InvalidSPDXAnalysisException {
        String hashValue = calculateHash(data, algorithm);
        var hash = new Hash(modelStore, uri("hash-" + (++spdxIdCounter)), copyManager, true, null);
        hash.setAlgorithm(spdxAlgorithm);
        hash.setHashValue(hashValue);
        pkg.getVerifiedUsings().add(hash);
    }

    private void addRelationships(Sbom sbom, ApplicationComponent mainComponent,
            Collection<ApplicationComponent> components) throws InvalidSPDXAnalysisException {

        addDependencyRelationships(sbom, mainComponent);
        for (var comp : components) {
            addDependencyRelationships(sbom, comp);
        }
    }

    private void addDependencyRelationships(Sbom sbom, ApplicationComponent component)
            throws InvalidSPDXAnalysisException {
        var dependencies = component.getDependencies();
        if (dependencies == null || dependencies.isEmpty()) {
            return;
        }

        String sourceSpdxId = componentToSpdxId.get(getComponentKey(component));
        if (sourceSpdxId == null) {
            return;
        }

        var sourceElement = new SpdxPackage(modelStore, uri(sourceSpdxId), copyManager, false, null);

        for (var depCoords : sortAlphabetically(dependencies)) {
            String depKey = depCoords.getGroupId() + ":" + depCoords.getArtifactId() + ":" + depCoords.getVersion();
            String targetSpdxId = componentToSpdxId.get(depKey);
            if (targetSpdxId == null) {
                continue;
            }

            var targetElement = new SpdxPackage(modelStore, uri(targetSpdxId), copyManager, false, null);

            var relationship = new Relationship(modelStore,
                    uri("rel-" + sourceSpdxId + "-" + targetSpdxId),
                    copyManager, true, null);
            relationship.setCreationInfo(creationInfo);
            relationship.setFrom(sourceElement);
            relationship.getTos().add(targetElement);
            relationship.setRelationshipType(RelationshipType.DEPENDS_ON);

            sbom.getElements().add(relationship);
        }
    }

    private Path getOutputFile() {
        if (getConfiguredOutputFile() != null) {
            return getConfiguredOutputFile();
        }
        var fileName = stripExtension(getManifest().getRunnerPath().getFileName().toString()) + "-spdx.json";
        return getOutputDir() == null ? Path.of(fileName) : getOutputDir().resolve(fileName);
    }
}
