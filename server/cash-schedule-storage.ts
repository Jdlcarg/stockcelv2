
import { db } from "./storage";
import { eq, and } from "drizzle-orm";
import { pgTable, serial, integer, boolean, text, timestamp } from "drizzle-orm/pg-core";

// Esquemas Drizzle para las nuevas tablas
export const cashScheduleConfig = pgTable("cash_schedule_config", {
  id: serial("id").primaryKey(),
  clientId: integer("client_id").notNull(),
  autoOpenEnabled: boolean("auto_open_enabled").default(false),
  autoCloseEnabled: boolean("auto_close_enabled").default(false),
  openHour: integer("open_hour").default(9),
  openMinute: integer("open_minute").default(0),
  closeHour: integer("close_hour").default(18),
  closeMinute: integer("close_minute").default(0),
  activeDays: text("active_days").default("1,2,3,4,5,6,7"),
  timezone: text("timezone").default("America/Argentina/Buenos_Aires"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const cashAutoOperationsLog = pgTable("cash_auto_operations_log", {
  id: serial("id").primaryKey(),
  clientId: integer("client_id").notNull(),
  operationType: text("operation_type").notNull(),
  cashRegisterId: integer("cash_register_id"),
  scheduledTime: timestamp("scheduled_time"),
  executedTime: timestamp("executed_time").defaultNow(),
  status: text("status").default("success"),
  errorMessage: text("error_message"),
  reportId: integer("report_id"),
  notes: text("notes"),
  createdAt: timestamp("created_at").defaultNow(),
});

export class CashScheduleStorage {
  // Obtener configuración de horarios para un cliente
  async getScheduleConfig(clientId: number) {
    try {
      console.log(`🔍 [DEBUG] getScheduleConfig called for clientId: ${clientId}`);
      
      const [config] = await db
        .select()
        .from(cashScheduleConfig)
        .where(eq(cashScheduleConfig.clientId, clientId));
      
      console.log(`🔍 [DEBUG] Raw DB result for clientId ${clientId}:`, JSON.stringify(config, null, 2));
      
      if (config) {
        console.log(`🔍 [DEBUG] Parsed config values:`, {
          openHour: config.openHour,
          openMinute: config.openMinute,
          closeHour: config.closeHour,
          closeMinute: config.closeMinute,
          autoOpenEnabled: config.autoOpenEnabled,
          autoCloseEnabled: config.autoCloseEnabled
        });
      }
      
      return config || null;
    } catch (error) {
      console.error('Error getting schedule config:', error);
      return null;
    }
  }

  // Crear o actualizar configuración de horarios
  async upsertScheduleConfig(clientId: number, configData: any) {
    try {
      const existingConfig = await this.getScheduleConfig(clientId);
      
      // Prepare data with proper timestamp handling
      const cleanData = {
        autoOpenEnabled: configData.autoOpenEnabled || false,
        autoCloseEnabled: configData.autoCloseEnabled || false,
        openHour: parseInt(configData.openHour) || 9,
        openMinute: parseInt(configData.openMinute) || 0,
        closeHour: parseInt(configData.closeHour) || 18,
        closeMinute: parseInt(configData.closeMinute) || 0,
        activeDays: configData.activeDays || "1,2,3,4,5,6,7",
        timezone: configData.timezone || "America/Argentina/Buenos_Aires",
      };
      
      if (existingConfig) {
        // Actualizar existente
        const [updated] = await db
          .update(cashScheduleConfig)
          .set({
            ...cleanData,
            updatedAt: new Date(),
          })
          .where(eq(cashScheduleConfig.clientId, clientId))
          .returning();
        
        return updated;
      } else {
        // Crear nuevo
        const [created] = await db
          .insert(cashScheduleConfig)
          .values({
            clientId,
            ...cleanData,
            createdAt: new Date(),
            updatedAt: new Date(),
          })
          .returning();
        
        return created;
      }
    } catch (error) {
      console.error('Error upserting schedule config:', error);
      throw error;
    }
  }

  // Registrar operación automática en el log
  async logAutoOperation(operationData: {
    clientId: number;
    operationType: string;
    cashRegisterId?: number;
    scheduledTime?: Date;
    status?: string;
    errorMessage?: string;
    reportId?: number;
    notes?: string;
  }) {
    try {
      const [logged] = await db
        .insert(cashAutoOperationsLog)
        .values(operationData)
        .returning();
      
      return logged;
    } catch (error) {
      console.error('Error logging auto operation:', error);
      throw error;
    }
  }

  // Obtener log de operaciones automáticas
  async getAutoOperationsLog(clientId: number, limit = 50) {
    try {
      const logs = await db
        .select()
        .from(cashAutoOperationsLog)
        .where(eq(cashAutoOperationsLog.clientId, clientId))
        .orderBy(cashAutoOperationsLog.executedTime)
        .limit(limit);
      
      return logs;
    } catch (error) {
      console.error('Error getting auto operations log:', error);
      return [];
    }
  }

  // Verificar si debe ejecutarse una operación automática
  async shouldExecuteAutoOperation(clientId: number, operationType: 'open' | 'close'): Promise<boolean> {
    try {
      const config = await this.getScheduleConfig(clientId);
      if (!config) return false;

      // Obtener hora actual en Argentina usando Intl.DateTimeFormat
      const now = new Date();
      const argentinaTime = new Date(now.toLocaleString("en-US", {timeZone: "America/Argentina/Buenos_Aires"}));

      const currentDay = argentinaTime.getDay() || 7; // Convert Sunday (0) to 7
      const activeDays = config.activeDays?.split(',').map(d => parseInt(d)) || [];
      
      // Verificar si hoy es un día activo
      if (!activeDays.includes(currentDay)) {
        return false;
      }

      const currentHour = argentinaTime.getHours();
      const currentMinute = argentinaTime.getMinutes();

      // Verificar si ya se ejecutó esta operación en esta hora específica
      const hasExecutedThisHour = await this.hasExecutedOperationThisHour(clientId, operationType, argentinaTime);
      if (hasExecutedThisHour) {
        return false;
      }

      if (operationType === 'open' && config.autoOpenEnabled) {
        const shouldExecute = currentHour === (config.openHour || 9) && currentMinute === (config.openMinute || 0);
        
        if (shouldExecute) {
          console.log(`🕐 Should execute AUTO OPEN for client ${clientId}: Argentina time ${argentinaTime.toLocaleString()}, configured time ${config.openHour}:${config.openMinute?.toString().padStart(2, '0')}`);
        }
        
        return shouldExecute;
      }

      if (operationType === 'close' && config.autoCloseEnabled) {
        const shouldExecute = currentHour === (config.closeHour || 18) && currentMinute === (config.closeMinute || 0);
        
        if (shouldExecute) {
          console.log(`🕐 Should execute AUTO CLOSE for client ${clientId}: Argentina time ${argentinaTime.toLocaleString()}, configured time ${config.closeHour}:${config.closeMinute?.toString().padStart(2, '0')}`);
        }
        
        return shouldExecute;
      }

      return false;
    } catch (error) {
      console.error('Error checking auto operation:', error);
      return false;
    }
  }

  // Verificar si ya se ejecutó una operación en esta hora específica
  private async hasExecutedOperationThisHour(clientId: number, operationType: string, currentTime: Date): Promise<boolean> {
    try {
      const hourStart = new Date(currentTime);
      hourStart.setMinutes(0, 0, 0);
      
      const hourEnd = new Date(currentTime);
      hourEnd.setMinutes(59, 59, 999);

      const recentLogs = await db
        .select()
        .from(cashAutoOperationsLog)
        .where(
          and(
            eq(cashAutoOperationsLog.clientId, clientId),
            eq(cashAutoOperationsLog.operationType, `auto_${operationType}`),
            eq(cashAutoOperationsLog.status, 'success')
          )
        )
        .orderBy(cashAutoOperationsLog.executedTime)
        .limit(1);

      if (recentLogs.length === 0) return false;

      const lastExecution = new Date(recentLogs[0].executedTime);
      return lastExecution >= hourStart && lastExecution <= hourEnd;
    } catch (error) {
      console.error('Error checking execution history:', error);
      return false;
    }
  }

  // Obtener próximas operaciones programadas
  async getScheduledOperations(clientId: number) {
    try {
      console.log(`🔍 [DEBUG] getScheduledOperations called for clientId: ${clientId}`);
      
      const config = await this.getScheduleConfig(clientId);
      console.log(`🔍 [DEBUG] Config retrieved in getScheduledOperations:`, JSON.stringify(config, null, 2));
      
      if (!config) {
        console.log(`🔍 [DEBUG] No config found for clientId: ${clientId}, returning empty array`);
        return [];
      }

      const operations = [];

      if (config.autoOpenEnabled) {
        console.log(`🔍 [DEBUG] Creating auto_open operation with hours: ${config.openHour}, minutes: ${config.openMinute}`);
        
        // MOSTRAR CONFIGURACIÓN EXACTA: usar fecha fija solo para display, horarios de configuración
        const configuredOpen = new Date('2025-01-01'); // Fecha fija para display
        
        // IMPORTANTE: Usar los valores EXACTOS de la DB sin fallbacks
        const openHour = config.openHour !== null && config.openHour !== undefined ? config.openHour : 9;
        const openMinute = config.openMinute !== null && config.openMinute !== undefined ? config.openMinute : 0;
        
        console.log(`🔍 [DEBUG] Setting open hours - config.openHour: ${config.openHour}, config.openMinute: ${config.openMinute}`);
        console.log(`🔍 [DEBUG] Resolved values - openHour: ${openHour}, openMinute: ${openMinute}`);
        
        configuredOpen.setHours(openHour, openMinute, 0, 0);

        console.log(`🔍 [DEBUG] configuredOpen after setHours:`, configuredOpen);
        console.log(`🔍 [DEBUG] configuredOpen hours/minutes:`, {
          hours: configuredOpen.getHours(),
          minutes: configuredOpen.getMinutes()
        });

        const openOperation = {
          type: 'auto_open',
          scheduledTime: configuredOpen,
          enabled: config.autoOpenEnabled,
        };
        
        console.log(`🔍 [DEBUG] Created openOperation:`, JSON.stringify(openOperation, null, 2));
        operations.push(openOperation);
      }

      if (config.autoCloseEnabled) {
        console.log(`🔍 [DEBUG] Creating auto_close operation with hours: ${config.closeHour}, minutes: ${config.closeMinute}`);
        
        // MOSTRAR CONFIGURACIÓN EXACTA: usar fecha fija solo para display, horarios de configuración
        const configuredClose = new Date('2025-01-01'); // Fecha fija para display
        
        // IMPORTANTE: Usar los valores EXACTOS de la DB sin fallbacks
        const closeHour = config.closeHour !== null && config.closeHour !== undefined ? config.closeHour : 18;
        const closeMinute = config.closeMinute !== null && config.closeMinute !== undefined ? config.closeMinute : 0;
        
        console.log(`🔍 [DEBUG] Setting close hours - config.closeHour: ${config.closeHour}, config.closeMinute: ${config.closeMinute}`);
        console.log(`🔍 [DEBUG] Resolved values - closeHour: ${closeHour}, closeMinute: ${closeMinute}`);
        
        configuredClose.setHours(closeHour, closeMinute, 0, 0);

        console.log(`🔍 [DEBUG] configuredClose after setHours:`, configuredClose);
        console.log(`🔍 [DEBUG] configuredClose hours/minutes:`, {
          hours: configuredClose.getHours(),
          minutes: configuredClose.getMinutes()
        });

        const closeOperation = {
          type: 'auto_close',
          scheduledTime: configuredClose,
          enabled: config.autoCloseEnabled,
        };
        
        console.log(`🔍 [DEBUG] Created closeOperation:`, JSON.stringify(closeOperation, null, 2));
        operations.push(closeOperation);
      }

      console.log(`🔍 [DEBUG] Final operations array for clientId ${clientId}:`, JSON.stringify(operations, null, 2));
      console.log(`🕐 Scheduled operations for client ${clientId}: Configuration shows Open:${config.openHour}:${config.openMinute?.toString().padStart(2, '0')} Close:${config.closeHour}:${config.closeMinute?.toString().padStart(2, '0')}`);
      
      return operations;
    } catch (error) {
      console.error('Error getting scheduled operations:', error);
      return [];
    }
  }
}

// Exportar instancia singleton
export const cashScheduleStorage = new CashScheduleStorage();
