package policy

// Vision models come from Hugging Face, each repo pinned to one revision and
// each file to its digest. Hugging Face serves large files from its CDN, so
// the route follows redirects to HuggingFaceRedirectHosts and nowhere else.
const HuggingFaceBase = "https://huggingface.co/"

// A host starting with "." matches any subdomain of it.
var HuggingFaceRedirectHosts = []string{"huggingface.co", ".hf.co"}

// VisionRepo is one Hugging Face repo at a fixed revision.
type VisionRepo struct {
	Revision string               `json:"revision"`
	Files    map[string]ModelFile `json:"files"`
}

// VisionModels is every vision model file, keyed by repo. Each file is a
// destination named "vision.<repo>/<file>", and its download must match the
// digest here.
var VisionModels = map[string]VisionRepo{
	// GLM-OCR for MLX, on macOS.
	"mlx-community/GLM-OCR-4bit": {
		Revision: "97f587506984cc92fa69b2694b4128e53db6b081",
		Files: map[string]ModelFile{
			"chat_template.jinja":          {SHA256: "062e7ee4cc8defa88a5938b5d456dc60366ffd80647f918946ee747bf09ddc7c", Size: 4606},
			"config.json":                  {SHA256: "c5c23ce928b8ccd72468c36de821a4132091e7bfc8dc3011e4349acafa63b72a", Size: 2080},
			"generation_config.json":       {SHA256: "4e2a3412f65b2a21d315d928986c55723d3e60dfb92c3982a5b9fd56835b0aa5", Size: 165},
			"model.safetensors":            {SHA256: "089e0339fcbc0fbf2225c3bd1cd94c6b4d49fdb3b1adfbb35ea22eb60b2afc95", Size: 1247191941},
			"model.safetensors.index.json": {SHA256: "191dea2bf69e8d0ec156ce87be21044ae28a1dd6a3418a35b2df4b36478daa39", Size: 55990},
			"preprocessor_config.json":     {SHA256: "02cc50c36240882ae35e8cd4077a25a379664108185d728d261cb785aefeccff", Size: 367},
			"processor_config.json":        {SHA256: "19dafea5bd6415c50e2da43a31583dab39f9496673260ad33d9fa6c638a1d077", Size: 597},
			"tokenizer.json":               {SHA256: "aa0fd058c73a5718bb191f6672dc16d122ee0147b20c123d1726514298f9968a", Size: 6838609},
			"tokenizer_config.json":        {SHA256: "7a76fcb27abbc2cb0249d81884fef972b2c27194e3e13db54baae50f58f141fb", Size: 1066},
		},
	},
	// GLM-OCR for llama.cpp, on Windows.
	"ggml-org/GLM-OCR-GGUF": {
		Revision: "65a42de1148dbed2297e922b5dbc7d9b70c36578",
		Files: map[string]ModelFile{
			"GLM-OCR-Q8_0.gguf":        {SHA256: "45bc244a6446aff850521dc41f18bc8d7105ad5f0c2c8c28af04e7cc4f4d50b1", Size: 950433408},
			"mmproj-GLM-OCR-Q8_0.gguf": {SHA256: "9c4b58e33e316ed142eb5dcb41abec3844d3e6e5dc361ffb782c3fa9d175141f", Size: 484403648},
		},
	},
}

// VisionDestination names the destination that downloads file from repo.
func VisionDestination(repo, file string) string { return "vision." + repo + "/" + file }

func init() {
	for repo, r := range VisionModels {
		for file, f := range r.Files {
			Destinations[VisionDestination(repo, file)] = Destination{
				Route:  RouteHuggingFace,
				Method: "GET",
				Path:   repo + "/resolve/" + r.Revision + "/" + file,
				Accept: []string{""},
				Body:   Body{Kind: BodyNone},
				SHA256: f.SHA256,
			}
		}
	}
}
