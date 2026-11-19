# libSceIcu

## add Functional

- [Resource-bundle locale type lookup](../../../core/libs/prx/libSceIcu/ResourceBundle.cpp) follows ICU 68.2 status, argument and locale-type behavior through the pinned ICU 78.1 resource backend. Actual and valid locale names consequently use the bundled ICU data version rather than verified console data. Returned names are borrowed and must not race bundle close, reuse or cleanup. Foreign or stale handles and unusable guest status memory throw. Closes when: the ABI, locale names and data-version behavior are compared with the console.
