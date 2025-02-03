package keys

import (
	"context"
	"encoding/base64"
	"io"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/ovh/okms-cli/cmd/okms/common"
	"github.com/ovh/okms-cli/common/flagsmgmt"
	"github.com/ovh/okms-cli/common/output"
	"github.com/ovh/okms-cli/common/utils/exit"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func newDecryptWithServiceKeyCmd() *cobra.Command {
	var (
		useWrap    bool
		noProgress bool
		fromBase64 bool
		repeat     uint32
		context    string
	)

	cmd := &cobra.Command{
		Use:   "decrypt KEY-ID DATA [OUTPUT]",
		Short: "Decrypt data previously encrypted by Encrypt operation",
		Long: `Decrypt data previously encrypted by Encrypt operation.

DATA can be either plain text, a '-' to read from stdin, or a filename prefixed with @.
OUTPUT can be either a filepath, or a "-" for stdout. If not set, output is stdout.`,
		Args: cobra.RangeArgs(2, 3),
		Run: func(cmd *cobra.Command, args []string) {
			keyId := exit.OnErr2(uuid.Parse(args[0]))
			out := "-"
			if len(args) > 2 && args[2] != "" {
				out = args[2]
			}

			if useWrap {
				// If wrapping is enabled, we don't call Decrypt endpoint directly,
				// but instead extract data kaye from the blob, and use it to decrypt data
				ctx := []byte{}
				if context != "" {
					ctx = []byte(context)
				}
				exit.OnErr(wrapDecrypt(cmd.Context(), args[1], out, keyId, ctx, noProgress, fromBase64))
				return
			}

			text := flagsmgmt.BytesFromArg(args[1], 8192)
			c := common.Client()
			writer := flagsmgmt.WriterFromArg(out)
			var wg sync.WaitGroup
			defer writer.Close()
			for gn := range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range repeat / 16 {
						resp := exit.OnErr2(c.Decrypt(cmd.Context(), keyId, context, string(text)))
						if cmd.Flag("output").Value.String() == string(flagsmgmt.JSON_OUTPUT_FORMAT) {
							output.JsonPrint(resp)
						} else {
							exit.OnErr2(writer.Write([]byte(strconv.Itoa(int(gn)))))
							exit.OnErr2(writer.Write([]byte("-")))
							exit.OnErr2(writer.Write([]byte(strconv.Itoa(int(i)))))
							exit.OnErr2(writer.Write(resp))
							exit.OnErr2(writer.Write([]byte("\n")))
						}
					}
				}()
			}

			wg.Wait()
		},
	}

	cmd.Flags().BoolVar(&useWrap, "dk", false, "Decrypt locally using an embedded encrypted datakey")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "Do not display progress bar or spinner")
	cmd.Flags().BoolVar(&fromBase64, "base64", false, "When using a datakey, decrypts a base64 encoded input")
	cmd.Flags().Uint32Var(&repeat, "repeat", 1, "Repeat that operation n times")
	cmd.Flags().StringVar(&context, "context", "", "Optional encryption context (AAD)")
	return cmd
}

func wrapDecrypt(ctx context.Context, input, output string, keyId uuid.UUID, keyCtx []byte, noProgress, b64 bool) error {
	reader, size := flagsmgmt.ReaderFromArgWithSize(input)
	defer reader.Close()
	if !noProgress && output != "-" {
		bar := progressbar.DefaultBytes(size, "Decrypting")
		bReader := progressbar.NewReader(reader, bar)
		reader = &bReader
	}

	var in io.Reader = reader
	if b64 {
		in = base64.NewDecoder(base64.StdEncoding, reader)
	}

	out := flagsmgmt.WriterFromArg(output)
	defer out.Close()

	in, err := common.Client().DataKeys(keyId).DecryptStream(ctx, in, keyCtx)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return err
}
