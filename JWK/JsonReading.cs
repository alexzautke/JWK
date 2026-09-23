using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CreativeCode.JWK
{
    /// <summary>
    /// Reads JSON the way a JWK has to be read. By default Json.NET turns a string which looks like a date into a date,
    /// so a "kid" (or any other member) such as "2024-05-01T00:00:00Z" would no longer be a JSON string and would be
    /// written back in a different, culture dependent format. Every place where JSON enters this library therefore
    /// reads it with <see cref="DateParseHandling.None"/>, which keeps every string exactly as it was written.
    /// </summary>
    internal static class JsonReading
    {
        internal static readonly JsonSerializerSettings SerializerSettings = new JsonSerializerSettings
        {
            DateParseHandling = DateParseHandling.None
        };

        /// <summary>
        /// Parses a JSON object as <see cref="JObject.Parse(string)"/> does, but keeps every string as it was written.
        /// </summary>
        internal static JObject ParseObject(string json)
        {
            using (var reader = new JsonTextReader(new StringReader(json)) { DateParseHandling = DateParseHandling.None })
            {
                var jsonObject = JObject.Load(reader);
                while (reader.Read())
                {
                    // As JObject.Parse does: any content after the object other than a comment throws in the reader
                }

                return jsonObject;
            }
        }

        /// <summary>
        /// Loads a JSON object from a reader the caller has set up, keeping every string of it as it was written. Only
        /// the tokens which have not been read yet can be kept; the setting of the reader is restored afterwards.
        /// </summary>
        internal static JObject LoadObject(JsonReader reader)
        {
            var dateParseHandling = reader.DateParseHandling;
            reader.DateParseHandling = DateParseHandling.None;
            try
            {
                return JObject.Load(reader);
            }
            finally
            {
                reader.DateParseHandling = dateParseHandling;
            }
        }
    }
}
