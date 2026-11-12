rule PackweirQualificationMarker
{
    meta:
        description = "Harmless Packweir integration qualification marker; not malware"
    strings:
        $marker = "PACKWEIR_ASSEMBLYLINE_HARMLESS_MARKER_V1"
    condition:
        $marker
}
