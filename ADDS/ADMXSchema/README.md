# Group Policy ADMX Schema Files

This directory contains the [Group Policy ADMX Schema files](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/6e10478a-e9e6-4fdc-a1f6-bdd9bd7f2209) that were slightly modified to support the [multiText element](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/Policy/element-multitext). The schema files are used during ADMX and ADML file authoring for code completion (IntelliSense) and validation.

| File                        | Description        |
|-----------------------------|--------------------|
| `PolicyDefinitionFiles.xsd` | [ADMX File Schema] |
| `PolicyDefinitions.xsd`     | [ADMX Policy Definition Schema] |
| `BaseTypes.xsd`             | [Base ADMX Schema] |

[ADMX File Schema]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/ddeb37b6-22ab-4936-adc4-b9d7fe1de6e6
[Base ADMX Schema]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/81d92810-a6d2-4301-a607-b3ba34dc2989
[ADMX Policy Definition Schema]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/81a89003-5121-4216-b788-fde8daa71c78
