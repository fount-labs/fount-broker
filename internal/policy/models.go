package policy

// ModelFile is one embedding model file the broker may download.
type ModelFile struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ModelFiles is every model file, keyed by "<model>/<file>" under ModelsBase.
// Each is a destination named "models.<model>/<file>", and its download must
// match the digest here.
var ModelFiles = map[string]ModelFile{
	// bge-small-en-v1.5, the embedding model Fount ships. MLX on macOS,
	// ONNX (FastEmbed) on Windows.
	"bge-small-en-v1.5-bf16/config.json":        {SHA256: "cb9e758b43f5baf05b2f551dc8b25b2e972aa9e1788e8ef05c88a49dd0651d81", Size: 722},
	"bge-small-en-v1.5-bf16/model.safetensors":  {SHA256: "24b98ebfe6c7a76b703465db8b295185462023282ceaa4a0aec24608bf0f86a0", Size: 66742096},
	"bge-small-en-v1.5-bf16/tokenizer.json":     {SHA256: "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66", Size: 711396},
	"bge-small-en-v1.5/config.json":             {SHA256: "fa73f90bf92c8cace1fbcb709626306f2bdbc9ea3e5b5f94b440df9b6aa56350", Size: 683},
	"bge-small-en-v1.5/model.onnx":              {SHA256: "828e1496d7fabb79cfa4dcd84fa38625c0d3d21da474a00f08db0f559940cf35", Size: 133093490},
	"bge-small-en-v1.5/special_tokens_map.json": {SHA256: "b6d346be366a7d1d48332dbc9fdf3bf8960b5d879522b7799ddba59e76237ee3", Size: 125},
	"bge-small-en-v1.5/tokenizer.json":          {SHA256: "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66", Size: 711396},
	"bge-small-en-v1.5/tokenizer_config.json":   {SHA256: "9261e7d79b44c8195c1cada2b453e55b00aeb81e907a6664974b4d7776172ab3", Size: 366},
}

// ModelDestination names the destination that downloads key.
func ModelDestination(key string) string { return "models." + key }

func init() {
	for key, f := range ModelFiles {
		Destinations[ModelDestination(key)] = Destination{
			Route:  RouteModels,
			Method: "GET",
			Path:   key,
			Accept: []string{""},
			Body:   Body{Kind: BodyNone},
			SHA256: f.SHA256,
		}
	}
}
