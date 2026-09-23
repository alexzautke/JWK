using System;
using System.Globalization;

namespace CreativeCode.JWK.Tests
{
    /// <summary>
    /// Runs a test under the given culture and restores the previous one afterwards, so that a value which is
    /// formatted according to the current culture cannot pass by accident under the invariant culture.
    /// </summary>
    internal sealed class CultureScope : IDisposable
    {
        private readonly CultureInfo _previousCulture;

        public CultureScope(string culture)
        {
            _previousCulture = CultureInfo.CurrentCulture;
            CultureInfo.CurrentCulture = new CultureInfo(culture);
        }

        public void Dispose()
        {
            CultureInfo.CurrentCulture = _previousCulture;
        }
    }
}
