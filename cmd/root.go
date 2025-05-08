package cmd

import (
    "encoding/csv"
    "errors"
    "fmt"
    "io"
    "os"
    "sort"
    "strings"
    "time"

    "github.com/andyfeller/gh-dependency-report/internal/log"
    "github.com/cli/go-gh"
    "github.com/cli/go-gh/pkg/api"
    graphql "github.com/cli/shurcooL-graphql"
    "github.com/spf13/cobra"
    "go.uber.org/zap"
)

type cmdFlags struct {
    reposExclude []string
    reportFile   string
    debug        bool
    severity     string
}

func NewCmd() *cobra.Command {

    // Instantiate struct to contain values from cobra flags; arguments are handled within RunE
    cmdFlags := cmdFlags{}

    // Instantiate cobra command driving work from package
    // Closures are used for cobra command lifecycle hooks for access to cobra flags struct
    cmd := cobra.Command{
        Use:   "gh-dependabot-report [flags] owner [repo ...]",
        Short: "Generate vulnerability report of repositories using Dependabot data",
        Long:  "Generate a comprehensive security vulnerability report for repositories using GitHub's Dependabot data, including CVE information, severity, and fixed versions",
        Args:  cobra.MinimumNArgs(1),
        // Setup command lifecycle handler; cmd representing the cobra.Command being instantiated now
        RunE: func(cmd *cobra.Command, args []string) error {

            var err error
            var client api.GQLClient

            // Reinitialize logging if debugging was enabled
            if cmdFlags.debug {
                logger, _ := log.NewLogger(cmdFlags.debug)
                defer logger.Sync() // nolint:errcheck // not sure how to errcheck a deferred call like this
                zap.ReplaceGlobals(logger)
            }

            client, err = gh.GQLClient(&api.ClientOptions{
                Headers: map[string]string{
                    "Accept": "application/vnd.github.hawkgirl-preview+json",
                },
            })

            if err != nil {
                zap.S().Errorf("Error arose retrieving graphql client")
                return err
            }

            owner := args[0]
            repos := args[1:]

            if _, err := os.Stat(cmdFlags.reportFile); errors.Is(err, os.ErrExist) {
                return err
            }

            reportWriter, err := os.OpenFile(cmdFlags.reportFile, os.O_WRONLY|os.O_CREATE, 0644)

            if err != nil {
                return err
            }

            return runCmd(owner, repos, cmdFlags.reposExclude, cmdFlags.severity, newAPIGetter(client), reportWriter)
        },
    }

    // Determine default report file based on current timestamp; for more info see https://pkg.go.dev/time#pkg-constants
    reportFileDefault := fmt.Sprintf("dependabot-report-%s.csv", time.Now().Format("20060102150405"))

    // Configure flags for command
    cmd.Flags().StringSliceVarP(&cmdFlags.reposExclude, "exclude", "e", []string{}, "Repositories to exclude from report")
    cmd.Flags().StringVarP(&cmdFlags.reportFile, "output-file", "o", reportFileDefault, "Name of file to write CSV report")
    cmd.Flags().StringVarP(&cmdFlags.severity, "severity", "s", "", "Filter by severity (critical, high, moderate, low)")
    cmd.PersistentFlags().BoolVarP(&cmdFlags.debug, "debug", "d", false, "Whether to debug logging")

    return &cmd
}

func runCmd(owner string, repos []string, repoExcludes []string, severityFilter string, g Getter, reportWriter io.Writer) error {

    // Resolve repositories in scope of report
    if len(repos) <= 0 {
        repos = make([]string, 0, 100) // Struggle for initial slice length given potential growth for large organizations
        var reposCursor *string

        for {
            reposQuery, err := g.GetRepos(owner, reposCursor)

            if err != nil {
                return err
            }

            for _, repo := range reposQuery.RepositoryOwner.Repositories.Nodes {
                repos = append(repos, repo.Name)
            }

            reposCursor = &reposQuery.RepositoryOwner.Repositories.PageInfo.EndCursor

            if !reposQuery.RepositoryOwner.Repositories.PageInfo.HasNextPage {
                break
            }
        }
    }

    sort.Strings(repos)

    if len(repoExcludes) > 0 {
        sort.Strings(repoExcludes)
        zap.S().Debugf("Excluding repos", "repos", repoExcludes)

        for _, repoExclude := range repoExcludes {
            for i, repo := range repos {
                if repoExclude == repo {
                    repos = append(repos[:i], repos[i+1:]...)
                }
            }
        }
    }

    if len(repos) <= 0 {
        return errors.New("No repositories to report on")
    }

    zap.S().Infof("Processing repos: %s", repos)

    // Prepare writer for outputting report
    csvWriter := csv.NewWriter(reportWriter)

    err := csvWriter.Write([]string{
        "Owner",
        "Repo",
        "Alert Number",
        "State",
        "Package Name",
        "Package Manager",
        "Manifest Path",
        "Scope",
        "Current Version",
        "Severity",
        "GHSA ID",
        "CVE",
        "CVSS Score",
        "CVSS Vector",
        "CVSS V4 Score",
        "CWEs",
        "EPSS Percentage",
        "Vulnerable Version Range",
        "Fixed Version",
        "Advisory URL",
        "Published Date",
        "Updated Date",
        "Created Date",
        "Dismissed At",
        "Dismissed Reason",
        "Fixed At",
        "Summary",
        "Description",
    })
    

    if err != nil {
        return err
    }

    // Process each repository
    for _, repo := range repos {
        var vulnerabilityCursor *string
        zap.S().Debugf("Processing vulnerabilities for %s/%s", owner, repo)

        for {
            vulnQuery, err := g.GetVulnerabilities(owner, repo, severityFilter, vulnerabilityCursor)

            if err != nil {
                if strings.Contains(err.Error(), "Could not resolve") {
                    zap.S().Warnf("Repository %s/%s not found or no access", owner, repo)
                    break
                }
                return err
            }

            if vulnerabilityCursor == nil {
                zap.S().Infof("Processing %s/%s contains %d vulnerabilities", 
                    owner, 
                    repo, 
                    vulnQuery.Repository.VulnerabilityAlerts.TotalCount)
            }

            for _, vuln := range vulnQuery.Repository.VulnerabilityAlerts.Nodes {
                // Extract CVE and GHSA IDs from identifiers array
                var cveID, ghsaID string
                for _, identifier := range vuln.SecurityAdvisory.Identifiers {
                    if identifier.Type == "CVE" {
                        cveID = identifier.Value
                    } else if identifier.Type == "GHSA" {
                        ghsaID = identifier.Value
                    }
                }
                
                // Format CVSS scores and vectors
                cvssScore := fmt.Sprintf("%.1f", vuln.SecurityAdvisory.Cvss.Score)
                cvssVector := vuln.SecurityAdvisory.Cvss.VectorString
                var cvssV4Score string
                if vuln.SecurityAdvisory.CvssSeverities.CvssV4.Score > 0 {
                    cvssV4Score = fmt.Sprintf("%.1f", vuln.SecurityAdvisory.CvssSeverities.CvssV4.Score)
                }
                
                // Format CWEs
                var cwes string
                if len(vuln.SecurityAdvisory.Cwes) > 0 {
                    cwesList := make([]string, 0, len(vuln.SecurityAdvisory.Cwes))
                    for _, cwe := range vuln.SecurityAdvisory.Cwes {
                        cwesList = append(cwesList, cwe.CweID)
                    }
                    cwes = strings.Join(cwesList, ", ")
                }
                
                // Format EPSS percentage
                var epssPercentage string
                if len(vuln.SecurityAdvisory.Epss) > 0 && vuln.SecurityAdvisory.Epss[0].Percentage > 0 {
                    epssPercentage = fmt.Sprintf("%.5f", vuln.SecurityAdvisory.Epss[0].Percentage)
                }
                
                // Write vulnerability data to CSV
                err := csvWriter.Write([]string{
                    owner,
                    repo,
                    fmt.Sprintf("%d", vuln.Number),                                  // Alert Number
                    vuln.State,                                                      // State
                    vuln.Dependency.Package.Name,                                    // Package Name
                    vuln.Dependency.Package.Ecosystem,                               // Package Manager
                    vuln.Dependency.ManifestPath,                                    // Manifest Path
                    vuln.Dependency.Scope,                                           // Scope
                    vuln.VulnerableRequirements,                                     // Current Version
                    vuln.SecurityAdvisory.Severity,                                  // Severity
                    ghsaID,                                                          // GHSA ID
                    cveID,                                                           // CVE
                    cvssScore,                                                       // CVSS Score
                    cvssVector,                                                      // CVSS Vector
                    cvssV4Score,                                                     // CVSS V4 Score
                    cwes,                                                            // CWEs
                    epssPercentage,                                                  // EPSS Percentage
                    vuln.SecurityVulnerability.VulnerableVersionRange,               // Vulnerable Version Range
                    vuln.SecurityVulnerability.FirstPatchedVersion.Identifier,       // Fixed Version
                    vuln.SecurityAdvisory.Permalink,                                 // Advisory URL
                    vuln.SecurityAdvisory.PublishedAt,                               // Published Date
                    vuln.SecurityAdvisory.UpdatedAt,                                 // Updated Date
                    vuln.CreatedAt,                                                  // Created Date
                    vuln.DismissedAt,                                                // Dismissed At
                    vuln.DismissedReason,                                            // Dismissed Reason
                    vuln.FixedAt,                                                    // Fixed At
                    vuln.SecurityAdvisory.Summary,                                   // Summary
                    vuln.SecurityAdvisory.Description,                               // Description
                })

                if err != nil {
                    zap.S().Error("Error raised in writing output", zap.Error(err))
                }
            }

            vulnerabilityCursor = &vulnQuery.Repository.VulnerabilityAlerts.PageInfo.EndCursor

            if !vulnQuery.Repository.VulnerabilityAlerts.PageInfo.HasNextPage {
                break
            }
        }
    }

    csvWriter.Flush()
    return nil
}

// SecurityAdvisoryIdentifier represents a security identifier (like CVE, GHSA)
type SecurityAdvisoryIdentifier struct {
    Type  string
    Value string
}

// CVSS represents CVSS scoring information
type CVSS struct {
    VectorString string `graphql:"vectorString"`
    Score        float64
}

// CWE represents a Common Weakness Enumeration entry
type CWE struct {
    CweID string `graphql:"cweId"`
    Name  string
}

// EPSS represents Exploit Prediction Scoring System data
type EPSS struct {
    Percentage float64
    Percentile string
}

// SecurityReference represents a reference URL
type SecurityReference struct {
    URL string `graphql:"url"`
}

// Vulnerability represents a specific vulnerable package version in an advisory
type Vulnerability struct {
    Package struct {
        Ecosystem string
        Name      string
    }
    Severity               string
    VulnerableVersionRange string `graphql:"vulnerableVersionRange"`
    FirstPatchedVersion    struct {
        Identifier string
    } `graphql:"firstPatchedVersion"`
}

// SecurityAdvisory represents advisory information for a vulnerability
type SecurityAdvisory struct {
    GhsaID         string `graphql:"ghsaId"`
    CveID          string `graphql:"cveId"`
    Summary        string
    Description    string
    Severity       string
    Cvss           CVSS
    CvssSeverities struct {
        CvssV3 CVSS `graphql:"cvssV3"`
        CvssV4 CVSS `graphql:"cvssV4"`
    }
    Vulnerabilities []Vulnerability
    Epss            []EPSS
    Cwes            []CWE
    Identifiers     []SecurityAdvisoryIdentifier
    References      []SecurityReference
    PublishedAt     string
    UpdatedAt       string
    WithdrawnAt     string
    Permalink       string
}

// SecurityVulnerability represents the detected security vulnerability
type SecurityVulnerability struct {
    Package struct {
        Ecosystem string
        Name      string
    }
    Severity               string
    VulnerableVersionRange string `graphql:"vulnerableVersionRange"`
    FirstPatchedVersion    struct {
        Identifier string
    } `graphql:"firstPatchedVersion"`
}

// VulnerabilityAlert represents a Dependabot alert
type VulnerabilityAlert struct {
    Number                 int
    State                  string
    Dependency             struct {
        Package      struct {
            Ecosystem string
            Name      string
        }
        ManifestPath string
        Scope        string
    }
    SecurityAdvisory       SecurityAdvisory
    SecurityVulnerability  SecurityVulnerability
    URL                    string `graphql:"url"`
    HTMLUrl                string `graphql:"htmlUrl"`
    CreatedAt              string
    UpdatedAt              string
    DismissedAt            string
    DismissedBy            interface{}
    DismissedReason        string
    DismissedComment       string
    FixedAt                string
    VulnerableRequirements string
}

// VulnerabilityQuery represents the GraphQL query for vulnerability alerts
type VulnerabilityQuery struct {
    Repository struct {
        VulnerabilityAlerts struct {
            PageInfo struct {
                HasNextPage bool
                EndCursor   string
            }
            Nodes      []VulnerabilityAlert
            TotalCount int
        } `graphql:"vulnerabilityAlerts(first: 100, after: $endCursor, states: OPEN)"`
    } `graphql:"repository(owner: $owner, name: $repo)"`
}

// Existing queries from the original implementation
type reposQuery struct {
    RepositoryOwner struct {
        Repositories struct {
            Nodes []struct {
                Name string
            }
            PageInfo struct {
                HasNextPage bool
                EndCursor   string
            }
        } `graphql:"repositories(first: 100, after: $endCursor, ownerAffiliations: [OWNER])"`
    } `graphql:"repositoryOwner(login: $owner)"`
}

// Getter interface now includes vulnerability query
type Getter interface {
    GetRepos(owner string, endCursor *string) (*reposQuery, error)
    GetVulnerabilities(owner, repo string, severity string, endCursor *string) (*VulnerabilityQuery, error)
}

type APIGetter struct {
    client api.GQLClient
}

func newAPIGetter(client api.GQLClient) *APIGetter {
    return &APIGetter{
        client: client,
    }
}

func (g *APIGetter) GetRepos(owner string, endCursor *string) (*reposQuery, error) {
    query := new(reposQuery)
    variables := map[string]interface{}{
        "owner":     graphql.String(owner),
        "endCursor": (*graphql.String)(endCursor),
    }

    err := g.client.Query("getRepos", query, variables)
    return query, err
}

func (g *APIGetter) GetVulnerabilities(owner, repo string, severity string, endCursor *string) (*VulnerabilityQuery, error) {
    query := new(VulnerabilityQuery)
    variables := map[string]interface{}{
        "owner":     graphql.String(owner),
        "repo":      graphql.String(repo),
        "endCursor": (*graphql.String)(endCursor),
    }

    err := g.client.Query("getVulnerabilities", query, variables)

    // If there's a severity filter, filter the results in-memory
    // GitHub's API doesn't support filtering by severity directly
    if err == nil && severity != "" && len(query.Repository.VulnerabilityAlerts.Nodes) > 0 {
        var filteredNodes []VulnerabilityAlert
        for _, node := range query.Repository.VulnerabilityAlerts.Nodes {
            if strings.EqualFold(node.SecurityVulnerability.Severity, severity) {
                filteredNodes = append(filteredNodes, node)
            }
        }
        query.Repository.VulnerabilityAlerts.Nodes = filteredNodes
    }

    return query, err
}