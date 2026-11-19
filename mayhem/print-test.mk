# Prints what build.sh needs to link mayhem/cppunit_offline_main.cc with the test objects.
print-test-objects:
	@echo $(filter-out AllTest.$(OBJEXT),$(aria2c_OBJECTS))
print-test-libs:
	@echo $(aria2c_LDADD) $(LIBS)
print-test-cxxflags:
	@echo $(DEFS) $(DEFAULT_INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CXXFLAGS) $(CXXFLAGS)
