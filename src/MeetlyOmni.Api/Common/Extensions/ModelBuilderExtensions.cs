// <copyright file="ModelBuilderExtensions.cs" company="MeetlyOmni">
// Copyright (c) MeetlyOmni. All rights reserved.
// </copyright>

namespace MeetlyOmni.Api.Common.Extensions
{
    using System.Linq.Expressions;
    using System.Text.Json.Nodes;

    using Microsoft.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore.Metadata.Builders;
    using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

    public static class ModelBuilderExtensions
    {
        /// <summary>
        /// Configure non-nullable enum as string with optional default, type, and required.
        /// </summary>
        /// <returns></returns>
        public static PropertyBuilder<TEnum> ConfigureEnumAsString<TEntity, TEnum>(
            this EntityTypeBuilder<TEntity> builder,
            Expression<Func<TEntity, TEnum>> propertyExpression,
            int maxLength = 30,
            string? columnType = null,
            TEnum? defaultValue = null,
            bool isRequired = true)
            where TEntity : class
            where TEnum : struct, Enum
        {
            var converter = new EnumToStringConverter<TEnum>();
            var property = builder
                .Property(propertyExpression)
                .HasConversion(converter);

            return ApplyEnumPropertySettings(property, maxLength, columnType, defaultValue, isRequired);
        }

        /// <summary>
        /// Configure nullable enum as string with optional default, type, and required.
        /// </summary>
        /// <returns></returns>
        public static PropertyBuilder<TEnum?> ConfigureNullableEnumAsString<TEntity, TEnum>(
            this EntityTypeBuilder<TEntity> builder,
            Expression<Func<TEntity, TEnum?>> propertyExpression,
            int maxLength = 30,
            string? columnType = null,
            TEnum? defaultValue = null,
            bool isRequired = false)
            where TEntity : class
            where TEnum : struct, Enum
        {
            var converter = new ValueConverter<TEnum?, string>(
                v => v.HasValue ? v.Value.ToString() ! : null!,
                v => string.IsNullOrEmpty(v) ? (TEnum?)null : Enum.Parse<TEnum>(v));

            var property = builder
                .Property(propertyExpression)
                .HasConversion(converter);

            return ApplyEnumPropertySettings(property, maxLength, columnType, defaultValue, isRequired);
        }

        /// <summary>
        /// Configure JsonObject property as jsonb.
        /// </summary>
        /// <returns></returns>
        public static PropertyBuilder<JsonObject> ConfigureJsonbObject<TEntity>(
            this EntityTypeBuilder<TEntity> builder,
            Expression<Func<TEntity, JsonObject>> propertyExpression)
            where TEntity : class
        {
            return builder
                .Property(propertyExpression)
                .HasColumnType("jsonb");
        }

        /// <summary>
        /// Configure string with max length and required option.
        /// </summary>
        /// <returns></returns>
        public static PropertyBuilder<string> ConfigureString<TEntity>(
            this EntityTypeBuilder<TEntity> builder,
            Expression<Func<TEntity, string>> propertyExpression,
            int maxLength = 255,
            bool isRequired = true)
            where TEntity : class
        {
            var prop = builder.Property(propertyExpression).HasMaxLength(maxLength);
            return isRequired ? prop.IsRequired() : prop.IsRequired(false);
        }

        /// <summary>
        /// Configure List&lt;string&gt; as jsonb with default empty array.
        /// </summary>
        /// <returns></returns>
        public static PropertyBuilder<List<string>> ConfigureJsonbList<TEntity>(
            this EntityTypeBuilder<TEntity> builder,
            Expression<Func<TEntity, List<string>>> propertyExpression)
            where TEntity : class
        {
            return builder
                .Property(propertyExpression)
                .HasColumnType("jsonb")
                .HasDefaultValueSql("'[]'::jsonb");
        }

        /// <summary>
        /// Configure raw JSON string as jsonb column.
        /// </summary>
        /// <returns></returns>
        public static PropertyBuilder<string> ConfigureJsonbText<TEntity>(
            this EntityTypeBuilder<TEntity> builder,
            Expression<Func<TEntity, string>> propertyExpression)
            where TEntity : class
        {
            return builder
                .Property(propertyExpression)
                .HasColumnType("jsonb");
        }

        /// <summary>
        /// Shared logic for configuring enum/string/jsonb properties.
        /// </summary>
        private static PropertyBuilder<TProperty> ApplyEnumPropertySettings<TProperty>(
            PropertyBuilder<TProperty> property,
            int maxLength,
            string? columnType,
            object? defaultValue,
            bool isRequired)
        {
            property.HasMaxLength(maxLength);

            if (!string.IsNullOrEmpty(columnType))
            {
                property.HasColumnType(columnType);
            }

            if (defaultValue is not null)
            {
                property.HasDefaultValue(defaultValue);
            }

            return isRequired ? property.IsRequired() : property.IsRequired(false);
        }
    }
}
