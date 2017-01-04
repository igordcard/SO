class StagingStorePublisherProtocol:
    def on_recovery(self, staging_areas):
        pass

class StagingStoreProtocol(object):
    def on_staging_area_create(self, store):
        pass

    def on_staging_area_delete(self, store):
        pass