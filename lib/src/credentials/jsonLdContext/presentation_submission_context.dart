const String PRESENTATION_SUBMISSION_IRI =
    'https://identity.foundation/presentation-exchange/submission/v1/';
const Map<String, dynamic> PRESENTATION_SUBMISSION_CONTEXT = {
  "@context": {
    "@version": 1.1,
    "PresentationSubmission": {
      "@id":
          "https://identity.foundation/presentation-exchange/#presentation-submission",
      "@context": {
        "@version": 1.1,
        "presentation_submission": {
          "@id":
              "https://identity.foundation/presentation-exchange/#presentation-submission",
          "@type": "@json"
        }
      }
    }
  }
};
