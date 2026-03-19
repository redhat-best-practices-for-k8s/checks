package certification

import "regexp"

var (
	reImageWithTag = regexp.MustCompile(`^([^/]*)/*([^@]*):(.*)`)
	reImageDigest  = regexp.MustCompile(`^([^/]*)/(.*)@(.*:.*)`)
)

// parseContainerImage extracts registry, repository, tag, and digest from
// a container's image string and its imageID (from container status).
// This mirrors the parsing logic in certsuite's provider.buildContainerImageSource.
func parseContainerImage(image, imageID string) (registry, repository, tag, digest string) {
	match := reImageWithTag.FindStringSubmatch(image)
	if match != nil {
		if match[2] != "" {
			registry = match[1]
			repository = match[2]
			tag = match[3]
		} else {
			repository = match[1]
			tag = match[3]
		}
	}

	match = reImageDigest.FindStringSubmatch(imageID)
	if match != nil {
		digest = match[3]
	}

	return registry, repository, tag, digest
}
