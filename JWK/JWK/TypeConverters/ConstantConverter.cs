using System;
using System.ComponentModel;
using System.Globalization;

namespace JWK.TypeConverters
{
    public class ConstantConverter : TypeConverter
    {
        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
        {
            if (sourceType == typeof(string))
            {
                return true;
            }
            return base.CanConvertFrom(context, sourceType);
        }


        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
        {
            // No support for deserialization
            throw new NotImplementedException();
        }

    }
}
