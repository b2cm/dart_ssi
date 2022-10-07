const String presentationSubmissionContextIri =
    'https://identity.foundation/presentation-exchange/submission/v1/';
const Map<String, dynamic> presentationSubmissionContext = {
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
