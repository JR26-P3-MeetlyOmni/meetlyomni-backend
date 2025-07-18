using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using System.Text.Json.Nodes;

namespace MeetlyOmni.Api.Common.Extensions
{
    public static class ModelBuilderExtensions
    {
        /// <summary>
        /// Configure non-nullable enum as string with optional default, type, and required.
        /// </summary>
        public static PropertyBuilder<TEnum> ConfigureEnumAsString<TEnum>(
            this EntityTypeBuilder builder,
            string propertyName,
            int maxLength = 30,
            string? columnType = null,
            TEnum? defaultValue = null,
            bool isRequired = true
        ) where TEnum : struct, Enum
        {
            var converter = new EnumToStringConverter<TEnum>();

            var property = builder
                .Property<TEnum>(propertyName)
                .HasConversion(converter)
                .HasMaxLength(maxLength);

            if (!string.IsNullOrEmpty(columnType))
                property.HasColumnType(columnType);

            if (defaultValue is not null)
                property.HasDefaultValue(defaultValue.Value);

            if (isRequired)
                property.IsRequired();
            else
                property.IsRequired(false);

            return property;
        }

        /// <summary>
        /// Configure enum as string with optional default, type, and not required.
        /// </summary>
        public static PropertyBuilder<TEnum?> ConfigureNullableEnumAsString<TEnum>(
            this EntityTypeBuilder builder,
            string propertyName,
            int maxLength = 30,
            string? columnType = null,
            TEnum? defaultValue = null,
            bool isRequired = false
        ) where TEnum : struct, Enum
        {
            var converter = new ValueConverter<TEnum?, string>(
                v => v.HasValue ? v.Value.ToString()! : null!,
                v => string.IsNullOrEmpty(v) ? (TEnum?)null : Enum.Parse<TEnum>(v)
            );

            var property = builder
                .Property<TEnum?>(propertyName)
                .HasConversion(converter)
                .HasMaxLength(maxLength);

            if (!string.IsNullOrEmpty(columnType))
                property.HasColumnType(columnType);

            if (defaultValue is not null)
                property.HasDefaultValue(defaultValue.Value);

            if (isRequired)
                property.IsRequired();
            else
                property.IsRequired(false);

            return property;
        }


        /// <summary>
        /// Configure property as JSONB JsonObject.
        /// </summary>
        public static PropertyBuilder<JsonObject> ConfigureJsonbObject(
            this EntityTypeBuilder builder,
            string propertyName
        )
        {
            return builder
                .Property<JsonObject>(propertyName)
                .HasColumnType("jsonb");
        }

        /// <summary>
        /// Configure string with max length and required option.
        /// </summary>
        public static PropertyBuilder<string> ConfigureString(
            this EntityTypeBuilder builder,
            string propertyName,
            int maxLength = 255,
            bool isRequired = true
        )
        {
            var prop = builder.Property<string>(propertyName).HasMaxLength(maxLength);
            return isRequired ? prop.IsRequired() : prop.IsRequired(false);
        }

        /// <summary>
        /// Configure List<string> as jsonb list (Postgres).
        /// </summary>
        public static PropertyBuilder<List<string>> ConfigureJsonbList(
            this EntityTypeBuilder builder,
            string propertyName
        )
        {
            return builder.Property<List<string>>(propertyName)
                         .HasColumnType("jsonb")
                         .HasDefaultValueSql("'[]'::jsonb");
        }

        /// <summary>
        /// Configure raw json string as jsonb column.
        /// </summary>
        public static PropertyBuilder<string> ConfigureJsonbText(
            this EntityTypeBuilder builder,
            string propertyName
        )
        {
            return builder.Property<string>(propertyName)
                         .HasColumnType("jsonb");
        }
    }
}
