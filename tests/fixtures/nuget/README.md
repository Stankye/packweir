# Native signed NuGet fixture

`native-signed.nupkg` is a 5,061-byte local test package created on 2026-11-11 by
[`tests/e2e/nuget-fixture.sh`](../../e2e/nuget-fixture.sh) using .NET SDK 10.0.403
(`dotnet pack`, then `dotnet nuget sign`). Its package ID is
`Packweir.Private.Fixture`, version `1.0.0`. The source is the fixture script's
single C# class; the package declares MIT, under this repository's MIT license.

The author certificate and key were generated only for that qualification run.
Only the public signed package is retained here; no private key or PFX is stored
in this directory. The Rust test inspects ZIP/XML structure and retains original
manifest bytes. It does not verify signatures, certificate validity, timestamps,
or publisher trust. The short-lived certificate's expiration does not affect
these parser checks.

SHA-256: `85716bbffce73bf8fd051883a8d195a4bef5667bffab49c00e95e626136748f3`

Regenerating the fixture produces different certificate/signature bytes. The
end-to-end fixture independently verifies fresh signatures using an explicitly
configured local test author.
